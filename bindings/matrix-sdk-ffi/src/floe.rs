// Copyright 2026 Verji Tech AS
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! uniffi surface for the streaming FLOE file encryption.
//!
//! This exposes the `matrix-sdk-crypto` FLOE crypto core (the
//! [`FloeStreamEncryptor`]/`FloeStreamDecryptor` `std::io::Read` adapters) to
//! the generated bindings, without ever crossing the FFI boundary with a whole
//! file. The core adapters carry a lifetime (the mxc `url` bound as associated
//! data) and a const-generic segment size, so they cannot be exported as opaque
//! handles directly; instead the host supplies a byte **source** and **sink**
//! as callback interfaces, and the segment loop is driven here in Rust — the
//! only bytes that cross the boundary are one ≤256 KiB chunk at a time.
//!
//! Scope: this is the **native** (e.g. `.NET`) slice. The crypto runs
//! synchronously (hardware AES on native targets); the WASM/WebCrypto-hybrid
//! variant is a separate, later build (it needs the async AEAD path), so the
//! whole module is `cfg`-gated off `wasm`.

use std::io::{Error as IoError, Read};

use matrix_sdk::ruma::{
    OwnedMxcUri,
    serde::{Base64, base64::UrlSafe},
};
use matrix_sdk_base::crypto::{
    ENC_SEG_LEN, FloeEncryptedFile as CoreFloeEncryptedFile, FloeError as CoreFloeError,
    FloeJwk as CoreFloeJwk, FloeStreamEncryptor,
};
use matrix_sdk_common::{SendOutsideWasm, SyncOutsideWasm};
use url::Url;

use crate::client::Client;

/// The size of the plaintext/ciphertext chunk the pump moves per step. One FLOE
/// segment is 256 KiB, so a single-segment buffer keeps the working set small.
const PUMP_BUF_LEN: usize = 262_144;

/// A host-provided source of bytes to encrypt or decrypt.
///
/// The host returns up to `max_len` bytes per call; an **empty** vector signals
/// end of stream. The binding drives this until the stream is exhausted, so the
/// host never has to hand over the whole file at once.
#[matrix_sdk_ffi_macros::export(callback_interface)]
pub trait FloeByteSource: SyncOutsideWasm + SendOutsideWasm {
    /// Return up to `max_len` bytes from the stream, or an empty vector at end
    /// of stream.
    fn read_chunk(&self, max_len: u32) -> Result<Vec<u8>, FloeError>;
}

/// A host-provided sink for the produced bytes (ciphertext when encrypting,
/// plaintext when decrypting), delivered one ≤256 KiB chunk at a time.
#[matrix_sdk_ffi_macros::export(callback_interface)]
pub trait FloeByteSink: SyncOutsideWasm + SendOutsideWasm {
    /// Consume the next chunk of produced bytes.
    fn write_chunk(&self, chunk: Vec<u8>) -> Result<(), FloeError>;
}

/// A JWK `oct` block carrying the 32-byte FLOE root key, mirroring the
/// `matrix-sdk-crypto` type but with the key as a base64url string for the
/// bindings.
#[derive(uniffi::Record)]
pub struct FloeJwk {
    /// Key type — always `oct`.
    pub kty: String,
    /// Descriptive algorithm token (e.g. `FLOE-A256GCM-SHA384`).
    pub alg: String,
    /// The 32-byte root key, base64url-encoded.
    pub k: String,
    /// Whether the key is extractable.
    pub ext: bool,
    /// Permitted key operations.
    pub key_ops: Vec<String>,
}

/// The FLOE `file` block to embed in the room-encrypted event, returned by
/// [`floe_encrypt`] and passed back to [`floe_decrypt`].
#[derive(uniffi::Record)]
pub struct FloeEncryptedFile {
    /// The mxc location of the encrypted blob; bound into the FLOE associated
    /// data.
    pub url: String,
    /// The format discriminator; selects the FLOE reader. Authoritative.
    pub v: String,
    /// The FLOE root key as a JWK `oct` block.
    pub key: FloeJwk,
    /// The encrypted segment size (a Range-planning hint; the header is
    /// authoritative).
    pub enc_seg_len: u32,
    /// The plaintext length (a progress/indexing hint; FLOE protects truncation
    /// itself).
    pub size: u64,
}

/// Errors surfaced across the FLOE binding.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FloeError {
    /// FLOE decryption failed — most commonly a wrong key or `url` (the header
    /// tag didn't validate), or a truncated stream.
    #[error("FLOE decryption failed: {message}")]
    Decrypt {
        /// A human-readable description of the failure.
        message: String,
    },
    /// The file block isn't the expected FLOE version.
    #[error("unexpected FLOE version: {version}")]
    UnexpectedVersion {
        /// The `v` discriminator found on the block.
        version: String,
    },
    /// An I/O error from the host source/sink or the segment pump.
    #[error("FLOE I/O error: {message}")]
    Io {
        /// A human-readable description of the failure.
        message: String,
    },
}

impl From<CoreFloeError> for FloeError {
    fn from(error: CoreFloeError) -> Self {
        match error {
            CoreFloeError::UnexpectedVersion(version) => Self::UnexpectedVersion { version },
            CoreFloeError::Io(error) => Self::Io { message: error.to_string() },
            other => Self::Decrypt { message: other.to_string() },
        }
    }
}

/// Adapts a host [`FloeByteSource`] callback into a [`Read`], buffering any
/// bytes the host returns beyond what the current read asked for.
struct CallbackReader {
    source: Box<dyn FloeByteSource>,
    buffer: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl CallbackReader {
    fn new(source: Box<dyn FloeByteSource>) -> Self {
        Self { source, buffer: Vec::new(), pos: 0, eof: false }
    }
}

impl Read for CallbackReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.buffer.len() {
            if self.eof {
                return Ok(0);
            }
            let requested = out.len().min(PUMP_BUF_LEN) as u32;
            self.buffer = self.source.read_chunk(requested).map_err(IoError::other)?;
            self.pos = 0;
            if self.buffer.is_empty() {
                self.eof = true;
                return Ok(0);
            }
        }

        let n = (self.buffer.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buffer[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Adapts a host [`FloeByteSink`] into a [`Write`], forwarding each written
/// chunk straight to the sink.
struct CallbackWriter {
    sink: Box<dyn FloeByteSink>,
}

impl CallbackWriter {
    fn new(sink: Box<dyn FloeByteSink>) -> Self {
        Self { sink }
    }
}

impl std::io::Write for CallbackWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sink.write_chunk(buf.to_vec()).map_err(IoError::other)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Drive `reader` to exhaustion, handing each chunk to the sink.
fn pump(reader: &mut dyn Read, sink: &dyn FloeByteSink) -> Result<(), FloeError> {
    let mut buf = vec![0u8; PUMP_BUF_LEN];
    loop {
        let n = reader.read(&mut buf).map_err(|e| FloeError::Io { message: e.to_string() })?;
        if n == 0 {
            return Ok(());
        }
        sink.write_chunk(buf[..n].to_vec())?;
    }
}

/// FLOE-encrypt the bytes the `source` yields, streaming the encrypted blob to
/// the `sink`, and return the [`FloeEncryptedFile`] block to put in the
/// room-encrypted event.
///
/// A fresh random root key is generated and `url` is bound as associated data,
/// so the blob only validates when served from that mxc location.
#[matrix_sdk_ffi_macros::export]
fn floe_encrypt(
    source: Box<dyn FloeByteSource>,
    sink: Box<dyn FloeByteSink>,
    url: String,
) -> Result<FloeEncryptedFile, FloeError> {
    let mxc = OwnedMxcUri::from(url);
    let reader = CallbackReader::new(source);
    // Pin the segment size to the FLOE_V0 default; `new` can't infer the
    // const-generic on its own.
    let mut encryptor = FloeStreamEncryptor::<CallbackReader, ENC_SEG_LEN>::new(reader, &mxc);

    pump(&mut encryptor, sink.as_ref())?;

    Ok(encryptor.finish().into())
}

/// FLOE-decrypt the blob the `source` yields for `file`, streaming the
/// recovered plaintext to the `sink`.
///
/// The header is validated against the file's key and `url` before any segment
/// is decrypted; a wrong key/`url` or a truncated stream is an error.
#[matrix_sdk_ffi_macros::export]
fn floe_decrypt(
    file: FloeEncryptedFile,
    source: Box<dyn FloeByteSource>,
    sink: Box<dyn FloeByteSink>,
) -> Result<(), FloeError> {
    let core = file.into_core()?;
    let reader = CallbackReader::new(source);
    let mut decryptor = core.decryptor(reader)?;

    pump(&mut decryptor, sink.as_ref())
}

/// FLOE media transport — the streaming upload/download methods, exposed on the
/// FFI [`Client`] so bindings get the full flow (reserve mxc, resumable upload,
/// redirect download) and not just the crypto core. The plaintext is streamed
/// through the host `source`/`sink` callbacks; the whole file never crosses the
/// FFI boundary.
#[matrix_sdk_ffi_macros::export]
impl Client {
    /// FLOE-encrypt the bytes from `source` and stream the ciphertext to the
    /// resumable-upload `front_door` (tus 1.0 → S3), reserving an mxc and
    /// returning the [`FloeEncryptedFile`] block to embed in the room-encrypted
    /// event.
    pub async fn floe_upload(
        &self,
        source: Box<dyn FloeByteSource>,
        front_door: String,
    ) -> Result<FloeEncryptedFile, FloeError> {
        let front_door = Url::parse(&front_door)
            .map_err(|e| FloeError::Io { message: format!("invalid front door url: {e}") })?;
        let reader = CallbackReader::new(source);
        let file = self
            .inner
            .media()
            .upload_floe(reader, &front_door)
            .await
            .map_err(|e| FloeError::Io { message: e.to_string() })?;
        Ok(file.into())
    }

    /// Download and FLOE-decrypt the blob described by `file`, following the
    /// MSC3860 redirect to the object store and streaming the recovered
    /// plaintext to `sink`. Memory-bounded — one 256 KiB segment is held at a
    /// time.
    pub async fn floe_download(
        &self,
        file: FloeEncryptedFile,
        sink: Box<dyn FloeByteSink>,
    ) -> Result<(), FloeError> {
        let core = file.into_core()?;
        let writer = CallbackWriter::new(sink);
        self.inner
            .media()
            .get_floe_media_content_to(&core, writer)
            .await
            .map_err(|e| FloeError::Io { message: e.to_string() })?;
        Ok(())
    }
}

impl From<CoreFloeEncryptedFile> for FloeEncryptedFile {
    fn from(core: CoreFloeEncryptedFile) -> Self {
        // The core `FloeJwk` zeroizes on drop, so its fields can't be moved out;
        // clone the small metadata and encode the key.
        Self {
            url: core.url.to_string(),
            v: core.v.clone(),
            key: FloeJwk {
                kty: core.key.kty.clone(),
                alg: core.key.alg.clone(),
                k: core.key.k.encode(),
                ext: core.key.ext,
                key_ops: core.key.key_ops.clone(),
            },
            enc_seg_len: core.enc_seg_len,
            size: core.size,
        }
    }
}

impl FloeEncryptedFile {
    /// Rebuild the `matrix-sdk-crypto` [`CoreFloeEncryptedFile`] from the
    /// binding record, decoding the base64url root key into its 32 bytes.
    fn into_core(self) -> Result<CoreFloeEncryptedFile, FloeError> {
        let key_bytes = Base64::<UrlSafe, Vec<u8>>::parse(&self.key.k)
            .map_err(|e| FloeError::Decrypt { message: format!("invalid root key: {e}") })?
            .into_inner();
        let key_bytes: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| FloeError::Decrypt { message: "root key is not 32 bytes".to_owned() })?;

        Ok(CoreFloeEncryptedFile {
            url: OwnedMxcUri::from(self.url),
            v: self.v,
            key: CoreFloeJwk {
                kty: self.key.kty,
                alg: self.key.alg,
                k: Base64::new(key_bytes),
                ext: self.key.ext,
                key_ops: self.key.key_ops,
            },
            enc_seg_len: self.enc_seg_len,
            size: self.size,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use super::*;

    /// An in-memory byte source over a fixed buffer, handing out `max_len`
    /// bytes per call. Owned (`'static`) so it can back a `Box<dyn ...>`.
    struct VecSource {
        data: Mutex<VecDeque<u8>>,
    }

    impl VecSource {
        fn boxed(data: &[u8]) -> Box<Self> {
            Box::new(Self { data: Mutex::new(data.iter().copied().collect()) })
        }
    }

    impl FloeByteSource for VecSource {
        fn read_chunk(&self, max_len: u32) -> Result<Vec<u8>, FloeError> {
            let mut data = self.data.lock().unwrap();
            let n = (max_len as usize).min(data.len());
            Ok(data.drain(..n).collect())
        }
    }

    /// An in-memory sink collecting everything written. Shared via `Arc` so the
    /// test can read the result after the binding has consumed its handle.
    #[derive(Default)]
    struct VecSink {
        data: Mutex<Vec<u8>>,
    }

    impl VecSink {
        fn take(&self) -> Vec<u8> {
            std::mem::take(&mut self.data.lock().unwrap())
        }
    }

    impl FloeByteSink for Arc<VecSink> {
        fn write_chunk(&self, chunk: Vec<u8>) -> Result<(), FloeError> {
            self.data.lock().unwrap().extend_from_slice(&chunk);
            Ok(())
        }
    }

    fn roundtrip(plaintext: &[u8]) {
        let url = "mxc://verji.example/abc123".to_owned();

        // encrypt: plaintext -> blob + file block
        let blob = Arc::new(VecSink::default());
        let file = floe_encrypt(VecSource::boxed(plaintext), Box::new(blob.clone()), url).unwrap();
        let blob_bytes = blob.take();
        assert_eq!(file.size, plaintext.len() as u64);
        assert_eq!(file.enc_seg_len, 262_144);
        assert_eq!(file.v, "org.verji.msc4016.floe.v0");

        // decrypt: blob + file block -> plaintext
        let recovered = Arc::new(VecSink::default());
        floe_decrypt(file, VecSource::boxed(&blob_bytes), Box::new(recovered.clone())).unwrap();
        assert_eq!(recovered.take(), plaintext);
    }

    #[test]
    fn floe_ffi_roundtrip_small() {
        roundtrip(b"hello, streaming FLOE");
    }

    #[test]
    fn floe_ffi_roundtrip_multi_segment() {
        // > 2 segments of plaintext so non-final + final framing is exercised.
        let plaintext: Vec<u8> = (0..600_000).map(|i| (i % 251) as u8).collect();
        roundtrip(&plaintext);
    }

    #[test]
    fn floe_ffi_roundtrip_empty() {
        roundtrip(b"");
    }

    #[test]
    fn floe_ffi_wrong_url_fails() {
        let blob = Arc::new(VecSink::default());
        let mut file = floe_encrypt(
            VecSource::boxed(b"secret"),
            Box::new(blob.clone()),
            "mxc://verji.example/a".to_owned(),
        )
        .unwrap();
        let blob_bytes = blob.take();

        // Tamper with the bound url; the header tag must reject it.
        file.url = "mxc://verji.example/OTHER".to_owned();
        let sink = Arc::new(VecSink::default());
        let result = floe_decrypt(file, VecSource::boxed(&blob_bytes), Box::new(sink));
        assert!(matches!(result, Err(FloeError::Decrypt { .. })));
    }

    #[test]
    fn callback_writer_forwards_chunks() {
        use std::io::Write as _;

        let sink = Arc::new(VecSink::default());
        let mut writer = CallbackWriter::new(Box::new(sink.clone()));
        writer.write_all(b"hello ").unwrap();
        writer.write_all(b"world").unwrap();
        writer.flush().unwrap();
        assert_eq!(sink.take(), b"hello world");
    }
}

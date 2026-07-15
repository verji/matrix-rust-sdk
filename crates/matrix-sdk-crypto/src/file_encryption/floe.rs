// Copyright 2026 Verji AS
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

//! Streaming FLOE encryption for large encrypted files.
//!
//! This is the client implementation of the Verji streaming file format: a
//! random-access, key-committing AEAD ([FLOE]) carried in an
//! [`EncryptedFile`]-shaped block, used for files too large for the legacy
//! whole-file AES-256-CTR path in [`attachments`](super::attachments).
//!
//! The two paths live side by side and are selected by the `v` discriminator in
//! the file block (see [`FileEncryptionScheme`]): `v2` keeps decrypting through
//! the untouched [`AttachmentDecryptor`](super::AttachmentDecryptor);
//! [`FLOE_V0`] decrypts through [`FloeStreamDecryptor`].
//!
//! Unlike the legacy keystream wrapper, the FLOE adapter is a *segment-framing*
//! reader: it emits a 74-byte header once, then one
//! `final_len_marker ‖ aead_iv ‖ ciphertext ‖ tag` frame per fixed-size
//! segment, so a caller streams the file segment by segment and never has to
//! hold the whole thing in memory. The blob it produces and consumes is
//!
//! ```text
//! FLOE_HEADER (74 B) ‖ segment₀ (ENC_SEG_LEN) ‖ … ‖ final_segment (≤ ENC_SEG_LEN)
//! ```
//!
//! The mxc `url` of the blob is bound into the FLOE associated data, so a blob
//! served from a different location fails the header tag immediately.
//!
//! [FLOE]: https://github.com/Snowflake-Labs/floe-specification
//! [`EncryptedFile`]: ruma::events::room::EncryptedFile

use std::{
    fmt,
    io::{Error as IoError, Read},
};

use floe_rs::gcm::{FloeDecryptor, FloeEncryptor, FloeKey, Header, Segment};
use rand::{Rng, rng};
use ruma::{
    MxcUri, OwnedMxcUri,
    serde::{Base64, base64::UrlSafe},
};
use serde::{Deserialize, Serialize, de};
use serde_json::Value;
use thiserror::Error;
use zerocopy::IntoBytes;
use zeroize::Zeroize;

use super::MediaEncryptionInfo;

/// The format discriminator for the fixed-segment FLOE scheme (the only FLOE
/// version defined today).
pub const FLOE_V0: &str = "org.verji.msc4016.floe.v0";

/// The FLOE encrypted-segment size, 256 KiB.
///
/// Each non-final encrypted segment is exactly this many bytes; the final
/// segment is shorter. This is fixed for [`FLOE_V0`]; a future variable-segment
/// mode would ship as a new `v`.
pub const ENC_SEG_LEN: u32 = 262_144;

/// The descriptive `alg` token for the FLOE JWK.
///
/// This is informational metadata, not a Web Crypto algorithm — the raw key
/// bytes are handed to FLOE (which runs HKDF internally). The `v`
/// discriminator, not `alg`, selects the reader.
const FLOE_ALG: &str = "FLOE-A256GCM-SHA384";

/// The size of the FLOE root key.
const KEY_SIZE: usize = 32;

/// The per-segment framing marker that flags any non-final segment; the final
/// segment carries its own total encrypted length here instead.
const NON_FINAL_SEGMENT_MARKER: u32 = u32::MAX;

/// The length of the per-segment framing marker, in bytes.
const SEGMENT_MARKER_LEN: usize = 4;

/// Error type for FLOE streaming encryption and decryption.
#[derive(Debug, Error)]
pub enum FloeError {
    /// An I/O error happened while reading or writing the FLOE stream.
    #[error(transparent)]
    Io(#[from] IoError),
    /// The leading bytes of the blob couldn't be decoded as a FLOE header.
    #[error("the FLOE header could not be decoded: {0}")]
    HeaderDecode(floe_rs::HeaderDecodeError),
    /// A decryptor couldn't be constructed from the header, key and associated
    /// data — most commonly because the header tag didn't validate (a wrong
    /// key or a wrong `url`).
    #[error("the FLOE decryptor could not be constructed: {0}")]
    Decrypt(floe_rs::DecryptionError),
    /// The file block isn't a [`FLOE_V0`] block.
    #[error("the file block is not a FLOE {FLOE_V0} block (v = {0})")]
    UnexpectedVersion(String),
}

/// The FLOE root key, delivered as a JWK `oct` inside the room-encrypted event.
///
/// `alg` is descriptive metadata — the raw 32 bytes are handed to FLOE (which
/// runs HKDF internally), not imported as a Web Crypto key; the `v`
/// discriminator on the file block, not `alg`, selects the reader. The key is
/// redacted from `Debug` and zeroized on drop.
#[derive(Clone, Serialize, Deserialize)]
pub struct FloeJwk {
    /// Key type — always `oct`.
    pub kty: String,
    /// Descriptive algorithm token (e.g. `FLOE-A256GCM-SHA384`).
    pub alg: String,
    /// The 32-byte root key, base64url-encoded.
    pub k: Base64<UrlSafe, [u8; KEY_SIZE]>,
    /// Whether the key is extractable.
    pub ext: bool,
    /// Permitted key operations.
    pub key_ops: Vec<String>,
}

#[cfg(not(tarpaulin_include))]
impl fmt::Debug for FloeJwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FloeJwk")
            .field("kty", &self.kty)
            .field("alg", &self.alg)
            .field("ext", &self.ext)
            .field("key_ops", &self.key_ops)
            .finish_non_exhaustive()
    }
}

impl Drop for FloeJwk {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}

/// The FLOE `file` / `thumbnail_file` content block.
///
/// This is the FLOE counterpart of ruma's [`EncryptedFile`]; it is owned by
/// this crate rather than ruma so the format divergence stays inside the fork.
/// Compared with the legacy block it drops `iv` (FLOE's IV lives in the in-blob
/// header) and `hashes` (the header tag and per-segment AEAD tags authenticate
/// the stream), and adds `enc_seg_len`/`size` layout hints.
///
/// [`EncryptedFile`]: ruma::events::room::EncryptedFile
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FloeEncryptedFile {
    /// The mxc location of the encrypted file blob. Bound into the FLOE
    /// associated data.
    pub url: OwnedMxcUri,
    /// The format discriminator; selects the FLOE reader. Authoritative.
    pub v: String,
    /// The 32-byte FLOE root key, delivered as a JWK `oct` inside the
    /// room-encrypted event.
    pub key: FloeJwk,
    /// The segment size, for Range planning before the header is parsed. A
    /// hint; the authenticated header is authoritative.
    pub enc_seg_len: u32,
    /// The plaintext length, for final-segment indexing and progress. A hint;
    /// FLOE protects truncation itself.
    pub size: u64,
}

impl FloeEncryptedFile {
    /// Build a [`FloeStreamDecryptor`] for this file over a reader of its
    /// encrypted blob.
    ///
    /// The reader must start at the first byte of the blob (the FLOE header);
    /// the header is consumed and validated against this file's key and `url`
    /// before any segment is read.
    ///
    /// # Errors
    ///
    /// Returns [`FloeError::UnexpectedVersion`] if this isn't a [`FLOE_V0`]
    /// block, and a header/decrypt error if the blob's header doesn't validate
    /// against this file's key and `url`.
    pub fn decryptor<R: Read>(&self, reader: R) -> Result<FloeStreamDecryptor<'_, R>, FloeError> {
        if self.v != FLOE_V0 {
            return Err(FloeError::UnexpectedVersion(self.v.clone()));
        }

        let key = FloeKey::from(*self.key.k.as_inner());

        FloeStreamDecryptor::new(reader, &key, self.url.as_bytes())
    }
}

/// The encryption scheme of a `file` / `thumbnail_file` block, dispatched on
/// its `v` discriminator.
///
/// This is the read-time entry point: deserialize the block into this enum and
/// match on it to pick the legacy or the FLOE path. The legacy variant carries
/// the unchanged [`MediaEncryptionInfo`]; the FLOE variant carries a
/// [`FloeEncryptedFile`].
#[derive(Debug)]
pub enum FileEncryptionScheme {
    /// A legacy AES-CTR block (`v1`/`v2`), decrypted with the
    /// [`AttachmentDecryptor`](super::AttachmentDecryptor).
    Legacy(MediaEncryptionInfo),
    /// A FLOE block ([`FLOE_V0`]), decrypted with a [`FloeStreamDecryptor`].
    Floe(FloeEncryptedFile),
}

impl<'de> Deserialize<'de> for FileEncryptionScheme {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let is_floe = value.get("v").and_then(Value::as_str) == Some(FLOE_V0);

        if is_floe {
            FloeEncryptedFile::deserialize(value).map(Self::Floe).map_err(de::Error::custom)
        } else {
            MediaEncryptionInfo::deserialize(value).map(Self::Legacy).map_err(de::Error::custom)
        }
    }
}

/// Build the FLOE JWK `oct` block for a freshly generated root key.
///
/// Shared with the async ([`super::floe_async`]) driver so the JWK's `alg`,
/// `key_ops` and encoding stay defined in exactly one place.
pub(super) fn floe_jwk(key: &[u8; KEY_SIZE]) -> FloeJwk {
    FloeJwk {
        kty: "oct".to_owned(),
        alg: FLOE_ALG.to_owned(),
        k: Base64::new(*key),
        ext: true,
        key_ops: vec!["encrypt".to_owned(), "decrypt".to_owned()],
    }
}

/// Read exactly one FLOE header off the front of a blob.
fn read_header<R: Read>(reader: &mut R) -> Result<Header, FloeError> {
    let mut bytes = vec![0u8; Header::LENGTH];
    reader.read_exact(&mut bytes)?;
    Header::from_bytes(&bytes).map_err(FloeError::HeaderDecode)
}

/// Read up to `len` bytes from `reader`, stopping early only at end of stream.
fn read_up_to<R: Read>(reader: &mut R, len: usize) -> Result<Vec<u8>, IoError> {
    let mut buf = vec![0u8; len];
    let mut filled = 0;

    while filled < len {
        let read = reader.read(&mut buf[filled..])?;
        if read == 0 {
            break;
        }
        filled += read;
    }

    buf.truncate(filled);
    Ok(buf)
}

#[derive(Clone, Copy, PartialEq)]
enum EncryptState {
    /// The header still has to be emitted.
    Header,
    /// Segments are being emitted; the next plaintext chunk is buffered.
    Body,
    /// The final segment has been emitted.
    Done,
}

/// A [`Read`] adapter that FLOE-encrypts a plaintext reader into the streaming
/// file-blob layout.
///
/// Reading from it yields the 74-byte header followed by one encrypted segment
/// frame at a time. After the whole stream has been read, [`finish`] returns
/// the [`FloeEncryptedFile`] block (carrying the fresh root key and the
/// plaintext size) to put in the room-encrypted event.
///
/// `S` is the encrypted-segment size; it defaults to [`ENC_SEG_LEN`] and only
/// varies in tests.
///
/// [`finish`]: FloeStreamEncryptor::finish
pub struct FloeStreamEncryptor<'a, R: Read, const S: u32 = ENC_SEG_LEN> {
    reader: R,
    encryptor: FloeEncryptor<'a, S>,
    header_bytes: Vec<u8>,
    /// The bytes ready to hand to the consumer (header, then one segment
    /// frame).
    out: Vec<u8>,
    out_pos: usize,
    /// The next plaintext chunk, read ahead so the current one's finality is
    /// known.
    lookahead: Option<Vec<u8>>,
    segment_number: u64,
    plaintext_len: u64,
    url: OwnedMxcUri,
    key: FloeJwk,
    state: EncryptState,
}

#[cfg(not(tarpaulin_include))]
impl<R: Read, const S: u32> fmt::Debug for FloeStreamEncryptor<'_, R, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FloeStreamEncryptor")
            .field("url", &self.url)
            .field("segment_number", &self.segment_number)
            .field("plaintext_len", &self.plaintext_len)
            .finish_non_exhaustive()
    }
}

impl<'a, R: Read, const S: u32> FloeStreamEncryptor<'a, R, S> {
    /// Wrap `reader`, FLOE-encrypting its bytes under a fresh random key with
    /// `url` bound as associated data.
    ///
    /// # Panics
    ///
    /// Panics if the system RNG can't provide enough randomness for the key or
    /// the FLOE IV.
    pub fn new(reader: R, url: &'a MxcUri) -> Self {
        let mut key = [0u8; KEY_SIZE];
        rng().fill_bytes(&mut key);

        let floe_key = FloeKey::from(key);
        let encryptor = FloeEncryptor::<S>::new(&floe_key, url.as_bytes());
        let header_bytes = encryptor.header().as_bytes().to_vec();

        Self {
            reader,
            encryptor,
            header_bytes,
            out: Vec::new(),
            out_pos: 0,
            lookahead: None,
            segment_number: 0,
            plaintext_len: 0,
            url: url.to_owned(),
            key: floe_jwk(&key),
            state: EncryptState::Header,
        }
    }

    /// Consume the encryptor and produce the FLOE file block.
    ///
    /// Call this after the whole stream has been read; `size` reflects the
    /// plaintext consumed so far.
    pub fn finish(self) -> FloeEncryptedFile {
        FloeEncryptedFile {
            url: self.url,
            v: FLOE_V0.to_owned(),
            key: self.key,
            enc_seg_len: S,
            size: self.plaintext_len,
        }
    }

    /// Refill `out` with the header or the next encrypted segment.
    fn produce(&mut self) -> Result<(), IoError> {
        match self.state {
            EncryptState::Header => {
                self.out = std::mem::take(&mut self.header_bytes);
                self.out_pos = 0;
                self.lookahead = Some(read_up_to(&mut self.reader, self.encryptor.input_size())?);
                self.state = EncryptState::Body;
            }
            EncryptState::Body => {
                let chunk = self.lookahead.take().unwrap_or_default();
                let next = read_up_to(&mut self.reader, self.encryptor.input_size())?;
                let is_final = next.is_empty();

                let mut frame = vec![0u8; self.encryptor.output_size(&chunk)];
                self.encryptor
                    .encrypt_segment(&chunk, &mut frame, self.segment_number, is_final)
                    .map_err(IoError::other)?;

                self.out = frame;
                self.out_pos = 0;
                self.plaintext_len += chunk.len() as u64;
                self.segment_number += 1;

                if is_final {
                    self.state = EncryptState::Done;
                } else {
                    self.lookahead = Some(next);
                }
            }
            EncryptState::Done => {}
        }

        Ok(())
    }
}

impl<R: Read, const S: u32> Read for FloeStreamEncryptor<'_, R, S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.out_pos < self.out.len() {
                let n = (self.out.len() - self.out_pos).min(buf.len());
                buf[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
                self.out_pos += n;
                return Ok(n);
            }

            if self.state == EncryptState::Done {
                return Ok(0);
            }

            self.produce()?;
        }
    }
}

/// A [`Read`] adapter that FLOE-decrypts a streaming file blob back into
/// plaintext.
///
/// Construction consumes and validates the 74-byte header; reading then yields
/// decrypted plaintext, pulling and decrypting one encrypted segment at a time.
/// Each segment's framing marker tells the reader whether it's the final
/// segment, so the stream is decoded without knowing the total length up front,
/// and a truncated stream (a missing final segment) is an error.
///
/// `S` is the encrypted-segment size; it defaults to [`ENC_SEG_LEN`] and only
/// varies in tests.
pub struct FloeStreamDecryptor<'a, R: Read, const S: u32 = ENC_SEG_LEN> {
    reader: R,
    decryptor: FloeDecryptor<'a, S>,
    out: Vec<u8>,
    out_pos: usize,
    segment_number: u64,
    done: bool,
}

#[cfg(not(tarpaulin_include))]
impl<R: Read, const S: u32> fmt::Debug for FloeStreamDecryptor<'_, R, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FloeStreamDecryptor")
            .field("segment_number", &self.segment_number)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<'a, R: Read, const S: u32> FloeStreamDecryptor<'a, R, S> {
    /// Wrap `reader`, FLOE-decrypting its blob under `key` with
    /// `associated_data` (the mxc `url`) bound in.
    ///
    /// # Errors
    ///
    /// Returns a header/decrypt error if the leading header doesn't decode or
    /// its tag doesn't validate under `key` and `associated_data`.
    pub fn new(mut reader: R, key: &FloeKey, associated_data: &'a [u8]) -> Result<Self, FloeError> {
        let header = read_header(&mut reader)?;
        let decryptor =
            FloeDecryptor::<S>::new(key, associated_data, &header).map_err(FloeError::Decrypt)?;

        Ok(Self { reader, decryptor, out: Vec::new(), out_pos: 0, segment_number: 0, done: false })
    }

    /// Like [`new`](Self::new) but with an explicit AEAD rotation mask.
    ///
    /// [`FLOE_V0`] uses the default rotation, so this is only needed to decrypt
    /// blobs produced with a non-default mask (the cross-implementation
    /// rotation test vectors).
    ///
    /// # Errors
    ///
    /// As for [`new`](Self::new).
    pub fn with_rotation_mask(
        mut reader: R,
        key: &FloeKey,
        associated_data: &'a [u8],
        rotation_mask: u64,
    ) -> Result<Self, FloeError> {
        let header = read_header(&mut reader)?;
        let decryptor =
            FloeDecryptor::<S>::with_rotation_mask(key, associated_data, &header, rotation_mask)
                .map_err(FloeError::Decrypt)?;

        Ok(Self { reader, decryptor, out: Vec::new(), out_pos: 0, segment_number: 0, done: false })
    }

    /// Read the next encrypted segment frame off the stream and decrypt it into
    /// `out`.
    fn produce(&mut self) -> Result<(), IoError> {
        let mut frame = vec![0u8; S as usize];
        self.reader.read_exact(&mut frame[..SEGMENT_MARKER_LEN])?;

        let marker = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        let is_final = marker != NON_FINAL_SEGMENT_MARKER;

        if is_final {
            // The final segment's marker is its own total encrypted length.
            let total = marker as usize;
            if total < SEGMENT_MARKER_LEN || total > S as usize {
                return Err(IoError::other("invalid final FLOE segment length"));
            }
            frame.truncate(total);
        }

        self.reader.read_exact(&mut frame[SEGMENT_MARKER_LEN..])?;

        let segment = Segment::<S>::from_bytes(&frame, is_final).map_err(IoError::other)?;
        let mut plaintext = vec![0u8; segment.plaintext_size()];
        self.decryptor
            .decrypt_segment(&segment, &mut plaintext, self.segment_number)
            .map_err(IoError::other)?;

        self.out = plaintext;
        self.out_pos = 0;
        self.segment_number += 1;
        if is_final {
            self.done = true;
        }

        Ok(())
    }
}

impl<R: Read, const S: u32> Read for FloeStreamDecryptor<'_, R, S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.out_pos < self.out.len() {
                let n = (self.out.len() - self.out_pos).min(buf.len());
                buf[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
                self.out_pos += n;
                return Ok(n);
            }

            if self.done {
                return Ok(0);
            }

            self.produce()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use floe_rs::gcm::{FloeKey, Header};
    use ruma::OwnedMxcUri;
    use serde_json::json;

    use super::{
        ENC_SEG_LEN, FLOE_V0, FileEncryptionScheme, FloeStreamDecryptor, FloeStreamEncryptor,
    };

    /// The associated data the canonical FLOE test vectors were generated with.
    const KAT_AAD: &[u8] = b"This is AAD";
    /// `CUSTOM_ROTATION_MASK` from the floe-rs vector suite (the u64 bits of
    /// `-4i64`).
    const CUSTOM_ROTATION_MASK: u64 = u64::from_be_bytes((-4i64).to_be_bytes());
    /// FLOE per-segment framing overhead: 4 (marker) + 12 (AEAD IV) + 16 (tag).
    const SEG_OVERHEAD: usize = 32;

    /// Decrypt a canonical FLOE KAT *through the adapter* and assert it matches
    /// the expected plaintext. Decrypting a foreign fixed ciphertext can only
    /// succeed by genuinely interoperating.
    fn decrypt_kat<const S: u32>(ct_hex: &str, pt_hex: &str, rotation_mask: Option<u64>) {
        let ciphertext = hex::decode(ct_hex.trim()).expect("ct hex");
        let plaintext = hex::decode(pt_hex.trim()).expect("pt hex");

        let key = FloeKey::try_from([0u8; 32].as_slice()).expect("zero key");
        let mut decryptor = match rotation_mask {
            Some(mask) => FloeStreamDecryptor::<_, S>::with_rotation_mask(
                Cursor::new(ciphertext),
                &key,
                KAT_AAD,
                mask,
            )
            .expect("decryptor"),
            None => FloeStreamDecryptor::<_, S>::new(Cursor::new(ciphertext), &key, KAT_AAD)
                .expect("decryptor"),
        };

        let mut decrypted = Vec::new();
        decryptor.read_to_end(&mut decrypted).expect("decrypt");
        assert_eq!(plaintext, decrypted, "decrypted KAT mismatch");
    }

    // The full canonical FLOE KAT suite (22 vectors, all five reference impls),
    // vendored byte-identically from floe-specification/kats; mirrors floe-rs's
    // own `test_vector!` declarations (segment size + rotation mask per vector).
    macro_rules! kat {
        ($fn:ident, $name:literal, $seg:expr) => {
            #[test]
            fn $fn() {
                decrypt_kat::<$seg>(
                    include_str!(concat!("floe_test_vectors/", $name, "_ct.txt")),
                    include_str!(concat!("floe_test_vectors/", $name, "_pt.txt")),
                    None,
                );
            }
        };
        ($fn:ident, $name:literal, $seg:expr, rotation) => {
            #[test]
            fn $fn() {
                decrypt_kat::<$seg>(
                    include_str!(concat!("floe_test_vectors/", $name, "_ct.txt")),
                    include_str!(concat!("floe_test_vectors/", $name, "_pt.txt")),
                    Some(CUSTOM_ROTATION_MASK),
                );
            }
        };
    }

    kat!(kat_rust_64, "rust_GCM256_IV256_64", 64);
    kat!(kat_rust_4k, "rust_GCM256_IV256_4K", 4096);
    kat!(kat_rust_1m, "rust_GCM256_IV256_1M", { 1024 * 1024 });
    kat!(kat_rust_rotation, "rust_rotation", 40, rotation);

    kat!(kat_go_64, "go_GCM256_IV256_64", 64);
    kat!(kat_go_4k, "go_GCM256_IV256_4K", 4096);
    kat!(kat_go_1m, "go_GCM256_IV256_1M", { 1024 * 1024 });
    kat!(kat_go_rotation, "go_rotation", 40, rotation);

    kat!(kat_cpp_64, "cpp_GCM256_IV256_64", 64);
    kat!(kat_cpp_4k, "cpp_GCM256_IV256_4K", 4096);
    kat!(kat_cpp_1m, "cpp_GCM256_IV256_1M", { 1024 * 1024 });
    kat!(kat_cpp_rotation, "cpp_rotation", 40, rotation);

    kat!(kat_pub_java_64, "pub_java_GCM256_IV256_64", 64);
    kat!(kat_pub_java_4k, "pub_java_GCM256_IV256_4K", 4096);
    kat!(kat_pub_java_1m, "pub_java_GCM256_IV256_1M", { 1024 * 1024 });
    kat!(kat_pub_java_rotation, "pub_java_rotation", 40, rotation);

    kat!(kat_java_64, "java_GCM256_IV256_64", 64);
    kat!(kat_java_4k, "java_GCM256_IV256_4K", 4096);
    kat!(kat_java_1m, "java_GCM256_IV256_1M", { 1024 * 1024 });
    kat!(kat_java_rotation, "java_rotation", 40, rotation);

    kat!(kat_java_last_seg_aligned, "java_lastSegAligned", 40);
    kat!(kat_java_last_seg_empty, "java_lastSegEmpty", 40);

    fn mxc(s: &str) -> OwnedMxcUri {
        OwnedMxcUri::from(s)
    }

    /// The streaming blob round-trips at 256 KiB with the `url` bound as AAD,
    /// and a non-final encrypted segment is exactly `ENC_SEG_LEN`.
    #[test]
    fn wsa_roundtrip_256kib_multisegment() {
        let url = mxc("mxc://verji.example/abc123");
        let pt_per_seg = ENC_SEG_LEN as usize - SEG_OVERHEAD;
        // ~2.2 segments, to exercise non-final + final framing.
        let plaintext: Vec<u8> = (0..(pt_per_seg * 2 + 50_000)).map(|i| (i % 251) as u8).collect();

        let mut encryptor =
            FloeStreamEncryptor::<_, ENC_SEG_LEN>::new(Cursor::new(plaintext.clone()), &url);
        let mut blob = Vec::new();
        encryptor.read_to_end(&mut blob).expect("encrypt");
        let file = encryptor.finish();

        // The first segment is non-final, so its marker is the sentinel and the
        // header + that whole segment are exactly 74 + ENC_SEG_LEN bytes.
        assert_eq!(
            &blob[Header::LENGTH..Header::LENGTH + 4],
            &[0xFF, 0xFF, 0xFF, 0xFF],
            "first segment must be framed as non-final"
        );
        assert!(blob.len() > Header::LENGTH + ENC_SEG_LEN as usize, "expected multiple segments");

        assert_eq!(file.enc_seg_len, ENC_SEG_LEN);
        assert_eq!(file.size, plaintext.len() as u64);
        assert_eq!(file.v, FLOE_V0);

        let mut decryptor = file.decryptor(Cursor::new(blob)).expect("decryptor");
        let mut decrypted = Vec::new();
        decryptor.read_to_end(&mut decrypted).expect("decrypt");
        assert_eq!(plaintext, decrypted, "256 KiB round-trip mismatch");
    }

    /// An empty file round-trips: a header plus a single empty final segment.
    #[test]
    fn wsa_roundtrip_empty_file() {
        let url = mxc("mxc://verji.example/empty");
        let mut encryptor =
            FloeStreamEncryptor::<_, ENC_SEG_LEN>::new(Cursor::new(Vec::new()), &url);
        let mut blob = Vec::new();
        encryptor.read_to_end(&mut blob).expect("encrypt");
        let file = encryptor.finish();
        assert_eq!(file.size, 0);

        let mut decryptor = file.decryptor(Cursor::new(blob)).expect("decryptor");
        let mut decrypted = Vec::new();
        decryptor.read_to_end(&mut decrypted).expect("decrypt");
        assert!(decrypted.is_empty());
    }

    /// The mxc `url` is bound in, so decrypting under a different `url` fails
    /// the header tag at decryptor construction.
    #[test]
    fn wsa_wrong_url_aad_fails() {
        let url = mxc("mxc://verji.example/abc123");
        let mut encryptor =
            FloeStreamEncryptor::<_, ENC_SEG_LEN>::new(Cursor::new(b"hello".to_vec()), &url);
        let mut blob = Vec::new();
        encryptor.read_to_end(&mut blob).expect("encrypt");
        let mut file = encryptor.finish();

        file.url = mxc("mxc://verji.example/DIFFERENT");
        assert!(file.decryptor(Cursor::new(blob)).is_err(), "a wrong url-AAD must fail");
    }

    /// The FLOE header is 74 bytes.
    #[test]
    fn wsa_header_is_74_bytes() {
        assert_eq!(Header::LENGTH, 74, "the FLOE header is 74 bytes (10 + 32 + 32)");
    }

    /// The `v` discriminator routes a FLOE block to the FLOE variant and a
    /// legacy block to the legacy variant.
    #[test]
    fn dispatch_routes_on_version() {
        let floe = json!({
            "url": "mxc://verji.example/abc",
            "v": FLOE_V0,
            "key": {
                "kty": "oct",
                "alg": "FLOE-A256GCM-SHA384",
                "ext": true,
                "k": "Voq2nkPme_x8no5-Tjq_laDAdxE6iDbxnlQXxwFPgE4",
                "key_ops": ["encrypt", "decrypt"]
            },
            "enc_seg_len": 262_144,
            "size": 1234
        });

        match serde_json::from_value::<FileEncryptionScheme>(floe).expect("parse floe") {
            FileEncryptionScheme::Floe(file) => {
                assert_eq!(file.v, FLOE_V0);
                assert_eq!(file.enc_seg_len, ENC_SEG_LEN);
            }
            FileEncryptionScheme::Legacy(_) => panic!("expected the FLOE variant"),
        }

        let legacy = json!({
            "v": "v2",
            "key": {
                "kty": "oct",
                "alg": "A256CTR",
                "ext": true,
                "k": "Voq2nkPme_x8no5-Tjq_laDAdxE6iDbxnlQXxwFPgE4",
                "key_ops": ["decrypt", "encrypt"]
            },
            "iv": "i0DovxYdJEcAAAAAAAAAAA",
            "hashes": { "sha256": "ANdt819a8bZl4jKy3Z+jcqtiNICa2y0AW4BBJ/iQRAU" }
        });

        match serde_json::from_value::<FileEncryptionScheme>(legacy).expect("parse legacy") {
            FileEncryptionScheme::Legacy(_) => {}
            FileEncryptionScheme::Floe(_) => panic!("expected the legacy variant"),
        }
    }
}

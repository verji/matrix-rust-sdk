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

//! Async, hardware-accelerated FLOE encryption for the web target.
//!
//! This is the `async` sibling of the synchronous streaming FLOE adapter in
//! [`super::floe`]. Both produce and consume the exact same on-the-wire blob
//! (the [`super::floe`] module documents its layout), and both are selected by
//! the same `v` discriminator; they differ only in *where the per-segment AEAD
//! runs*.
//!
//! The synchronous adapter drives [`floe-rs`]'s synchronous RustCrypto AEAD.
//! That is correct on native targets with hardware AES, but on the web the only
//! hardware-accelerated AES-GCM is [`crypto.subtle`][SubtleCrypto], which is
//! **asynchronous** — a synchronous segment loop can't await it. Software AES
//! compiled to WASM is ~100× slower and can't move multi-gigabyte files.
//!
//! This module drives [`floe-rs`]'s **async streaming surface**
//! ([`floe_rs::gcm::AsyncFloeEncryptor`] / [`AsyncFloeDecryptor`]): the FLOE
//! framing and its one-per-file HKDF-SHA-384 key schedule stay in synchronous
//! Rust inside floe-rs, and *only* the per-segment AES-256-GCM primitive
//! crosses an injectable, `async` seam ([`FloeAeadBackend`], which is floe-rs's
//! [`AsyncFloeAead`]). The web build wires a `crypto.subtle` backend
//! ([`WebCryptoAeadBackend`]) into that seam; the seam stays injectable so a
//! browser-native JSPI backend (which would let the primitive be synchronous
//! again) can replace it later without touching the driver.
//!
//! The types here are thin wrappers that add the Matrix-specific envelope
//! concerns floe-rs deliberately doesn't model: a fresh random root key, the
//! mxc `url` as associated data, and the [`FloeEncryptedFile`] block for the
//! room event. The framing and key schedule are floe-rs's, verified against the
//! shared cross-implementation FLOE test vectors both in floe-rs's own suite
//! and in this module's tests.
//!
//! [FLOE]: https://github.com/Snowflake-Labs/floe-specification
//! [`floe-rs`]: floe_rs
//! [`AsyncFloeDecryptor`]: floe_rs::gcm::AsyncFloeDecryptor
//! [SubtleCrypto]: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto

use std::fmt;

/// The pluggable, `async` per-segment AEAD seam the streaming FLOE drivers
/// delegate to — floe-rs's [`AsyncFloeAead`](floe_rs::AsyncFloeAead),
/// re-exported under the name this module has always used.
///
/// FLOE's framing and its one-per-file HKDF stay in floe-rs (synchronous Rust);
/// only the AES-256-GCM of each ≤256 KiB segment crosses this seam. The web
/// build implements it over [`crypto.subtle`][SubtleCrypto] (whose operations
/// genuinely await) via `WebCryptoAeadBackend`; tests implement it
/// synchronously over RustCrypto.
///
/// [SubtleCrypto]: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
pub use floe_rs::AsyncFloeAead as FloeAeadBackend;
use floe_rs::{
    AsyncDecryptionError, AsyncEncryptionError,
    gcm::{
        AsyncFloeDecryptor as CoreDecryptor, AsyncFloeEncryptor as CoreEncryptor, FloeKey, Header,
        Segment,
    },
};
use rand::{Rng, rng};
use ruma::MxcUri;
use thiserror::Error;
use zerocopy::IntoBytes;
use zeroize::Zeroize;

use super::floe::{ENC_SEG_LEN, FLOE_V0, FloeEncryptedFile, floe_jwk};

/// The size of the FLOE root key (AES-256).
const KEY_SIZE: usize = 32;

/// The FLOE header length in bytes (74): parameters ‖ IV ‖ header tag. A
/// streaming decryptor reads exactly this many bytes off the front of a blob
/// before the first segment.
pub const FLOE_HEADER_LEN: usize = Header::LENGTH;

/// The plaintext bytes carried by one full [`FLOE_V0`] segment —
/// [`ENC_SEG_LEN`] minus the per-segment framing overhead. A streaming
/// encryptor feeds [`FloeAsyncEncryptor::encrypt_segment`] this many plaintext
/// bytes per non-final segment.
pub const FLOE_V0_PLAINTEXT_SEG_LEN: usize =
    ENC_SEG_LEN as usize - Segment::<ENC_SEG_LEN>::overhead();

/// Error type for the async FLOE driver.
#[derive(Debug, Error)]
pub enum FloeAsyncError {
    /// The pluggable AEAD backend failed. For [`FloeAeadBackend::open`] this
    /// includes an authentication failure (a tampered or truncated segment).
    #[error("the FLOE AEAD backend failed: {0}")]
    Aead(String),
    /// The blob, header, or a segment frame was structurally malformed.
    #[error("the FLOE blob is malformed: {0}")]
    Malformed(&'static str),
    /// The header tag did not validate against the supplied key and associated
    /// data — the wrong key, or a blob served from a different `url`.
    #[error("the FLOE header tag did not validate (wrong key or url)")]
    HeaderTag,
}

impl From<AsyncEncryptionError> for FloeAsyncError {
    fn from(error: AsyncEncryptionError) -> Self {
        match error {
            AsyncEncryptionError::Backend(message) => FloeAsyncError::Aead(message),
            // Configuration / plaintext-length / rng failures: surface as an AEAD
            // failure carrying floe-rs's own message.
            other => FloeAsyncError::Aead(other.to_string()),
        }
    }
}

impl From<AsyncDecryptionError> for FloeAsyncError {
    fn from(error: AsyncDecryptionError) -> Self {
        match error {
            AsyncDecryptionError::Backend(message) => FloeAsyncError::Aead(message),
            AsyncDecryptionError::InvalidHeaderTag => FloeAsyncError::HeaderTag,
            AsyncDecryptionError::SegmentDecodeError(_) => {
                FloeAsyncError::Malformed("a FLOE segment frame is malformed")
            }
            AsyncDecryptionError::SegmentAfterFinal => {
                FloeAsyncError::Malformed("a FLOE segment was supplied after the final one")
            }
            AsyncDecryptionError::ConfigurationError(_)
            | AsyncDecryptionError::InvalidParameters { .. } => {
                FloeAsyncError::Malformed("the FLOE parameters are invalid")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The async FLOE encryptor.
// ---------------------------------------------------------------------------

/// Encrypts a plaintext into the streaming FLOE blob one segment at a time,
/// delegating each segment's AES-256-GCM to a [`FloeAeadBackend`].
///
/// Call [`header`](Self::header) once, then [`encrypt_segment`] per plaintext
/// chunk (the caller decides which chunk is final, e.g. by reading one chunk
/// ahead), concatenating the header and every returned frame into the blob.
/// After the final segment, [`finish`](Self::finish) returns the
/// [`FloeEncryptedFile`] block (carrying the fresh root key and plaintext size)
/// for the room-encrypted event.
///
/// A plaintext chunk must be at most [`FLOE_V0_PLAINTEXT_SEG_LEN`] bytes; every
/// non-final chunk should be exactly that size so its frame is exactly `S`
/// bytes. `S` is the encrypted-segment size and defaults to [`ENC_SEG_LEN`].
///
/// [`encrypt_segment`]: Self::encrypt_segment
pub struct FloeAsyncEncryptor<'a, B: FloeAeadBackend, const S: u32 = ENC_SEG_LEN> {
    inner: CoreEncryptor<'a, B, S>,
    root_key: [u8; KEY_SIZE],
    url: &'a MxcUri,
    plaintext_len: u64,
}

#[cfg(not(tarpaulin_include))]
impl<B: FloeAeadBackend, const S: u32> fmt::Debug for FloeAsyncEncryptor<'_, B, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FloeAsyncEncryptor")
            .field("url", &self.url)
            .field("plaintext_len", &self.plaintext_len)
            .finish_non_exhaustive()
    }
}

impl<'a, B: FloeAeadBackend, const S: u32> FloeAsyncEncryptor<'a, B, S> {
    /// Start encrypting under a fresh random root key, with `url` bound as the
    /// FLOE associated data and the default AEAD rotation.
    ///
    /// # Panics
    ///
    /// Panics if the system RNG can't provide enough randomness for the root
    /// key or the FLOE IV.
    pub fn new(backend: B, url: &'a MxcUri) -> Self {
        let mut root_key = [0u8; KEY_SIZE];
        rng().fill_bytes(&mut root_key);

        // floe-rs generates the FLOE IV (default rotation) and derives the header
        // and message key; it panics if the system RNG fails, matching this
        // constructor's contract.
        let key = FloeKey::from(root_key);
        let inner = CoreEncryptor::<B, S>::new(backend, &key, url.as_bytes());

        Self { inner, root_key, url, plaintext_len: 0 }
    }

    /// The FLOE header ([`FLOE_HEADER_LEN`] bytes), ready before any segment is
    /// encrypted. It must be the first bytes of the blob.
    pub fn header(&self) -> &[u8] {
        self.inner.header().as_bytes()
    }

    /// Encrypt the next plaintext chunk into one segment frame
    /// (`marker ‖ nonce ‖ ciphertext ‖ tag`).
    ///
    /// `is_final` marks the last chunk; the caller determines it (typically by
    /// reading one chunk ahead). An empty final chunk is valid and produces the
    /// empty final segment of an empty or segment-aligned file.
    ///
    /// # Errors
    ///
    /// Returns [`FloeAsyncError::Aead`] if the backend fails to seal the
    /// segment (including importing the epoch key), or if the chunk length
    /// is invalid.
    pub async fn encrypt_segment(
        &mut self,
        plaintext: &[u8],
        is_final: bool,
    ) -> Result<Vec<u8>, FloeAsyncError> {
        let frame = self.inner.encrypt_segment(plaintext, is_final).await?;
        self.plaintext_len += plaintext.len() as u64;
        Ok(frame)
    }

    /// Produce the FLOE file block for the room-encrypted event, with `size`
    /// reflecting the plaintext encrypted so far. Call it after the final
    /// segment; it borrows rather than consumes, so the root key is zeroized
    /// only when the encryptor is dropped.
    pub fn finish(&self) -> FloeEncryptedFile {
        FloeEncryptedFile {
            url: self.url.to_owned(),
            v: FLOE_V0.to_owned(),
            key: floe_jwk(&self.root_key),
            enc_seg_len: S,
            size: self.plaintext_len,
        }
    }
}

impl<B: FloeAeadBackend, const S: u32> Drop for FloeAsyncEncryptor<'_, B, S> {
    fn drop(&mut self) {
        // floe-rs zeroizes its own derived key material on drop; we own only the
        // root key.
        self.root_key.zeroize();
    }
}

// ---------------------------------------------------------------------------
// The async FLOE decryptor.
// ---------------------------------------------------------------------------

/// Decrypts a streaming FLOE blob one segment at a time, delegating each
/// segment's AES-256-GCM to a [`FloeAeadBackend`].
///
/// Construct it from the [`FLOE_HEADER_LEN`]-byte header (which is validated
/// against the key and associated data), then feed each `S`-sized encrypted
/// segment frame from the blob body to
/// [`decrypt_segment`](Self::decrypt_segment) in order. Each segment's marker
/// tells the decryptor whether it is the final one, so a truncated stream (a
/// missing final segment) never silently succeeds.
///
/// `S` is the encrypted-segment size and defaults to [`ENC_SEG_LEN`].
pub struct FloeAsyncDecryptor<'a, B: FloeAeadBackend, const S: u32 = ENC_SEG_LEN> {
    inner: CoreDecryptor<'a, B, S>,
}

#[cfg(not(tarpaulin_include))]
impl<B: FloeAeadBackend, const S: u32> fmt::Debug for FloeAsyncDecryptor<'_, B, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FloeAsyncDecryptor").finish_non_exhaustive()
    }
}

impl<'a, B: FloeAeadBackend, const S: u32> FloeAsyncDecryptor<'a, B, S> {
    /// Build a decryptor from the blob's [`FLOE_HEADER_LEN`]-byte header,
    /// validating it against `key` and `associated_data` (the mxc `url`) under
    /// the default rotation.
    ///
    /// # Errors
    ///
    /// Returns [`FloeAsyncError::Malformed`] if `header` is too short, or
    /// [`FloeAsyncError::HeaderTag`] if the header tag doesn't validate (a
    /// wrong key or `url`).
    pub fn new(
        backend: B,
        header: &[u8],
        key: &[u8; KEY_SIZE],
        associated_data: &'a [u8],
    ) -> Result<Self, FloeAsyncError> {
        let header = Header::from_bytes(header)
            .map_err(|_| FloeAsyncError::Malformed("the FLOE header is malformed"))?;
        let key = FloeKey::from(*key);

        let inner = CoreDecryptor::<B, S>::new(backend, &key, associated_data, &header)?;

        Ok(Self { inner })
    }

    /// Like [`new`](Self::new) but with an explicit AEAD rotation mask.
    ///
    /// [`FLOE_V0`] uses the default rotation, so this is only needed to decrypt
    /// the cross-implementation rotation test vectors.
    ///
    /// # Errors
    ///
    /// As for [`new`](Self::new).
    pub fn new_with_rotation_mask(
        backend: B,
        header: &[u8],
        key: &[u8; KEY_SIZE],
        associated_data: &'a [u8],
        rotation_mask: u64,
    ) -> Result<Self, FloeAsyncError> {
        let header = Header::from_bytes(header)
            .map_err(|_| FloeAsyncError::Malformed("the FLOE header is malformed"))?;
        let key = FloeKey::from(*key);

        let inner = CoreDecryptor::<B, S>::with_rotation_mask(
            backend,
            &key,
            associated_data,
            &header,
            rotation_mask,
        )?;

        Ok(Self { inner })
    }

    /// Whether the final segment has been decrypted. A streaming caller stops
    /// feeding frames once this is `true`.
    pub fn is_done(&self) -> bool {
        self.inner.is_done()
    }

    /// Decrypt the next encrypted segment frame from the blob body.
    ///
    /// `frame` is one segment as laid out in the blob: `marker ‖ nonce ‖
    /// ciphertext ‖ tag`. Non-final frames are exactly `S` bytes; the final
    /// frame carries its own total length in the marker.
    ///
    /// # Errors
    ///
    /// Returns [`FloeAsyncError::Malformed`] if the frame is structurally
    /// invalid or arrives after the final segment, or [`FloeAsyncError::Aead`]
    /// if the segment fails authentication (a tampered or reordered segment).
    pub async fn decrypt_segment(&mut self, frame: &[u8]) -> Result<Vec<u8>, FloeAsyncError> {
        Ok(self.inner.decrypt_segment(frame).await?)
    }
}

// ---------------------------------------------------------------------------
// The web AEAD backend — AES-256-GCM via `crypto.subtle`.
// ---------------------------------------------------------------------------

/// The web ([`crypto.subtle`][SubtleCrypto]) implementation of the async AEAD
/// seam — the production [`FloeAeadBackend`] for the WASM target.
///
/// It delegates each segment's AES-256-GCM to the browser's
/// hardware-accelerated Web Crypto, awaited through `wasm-bindgen-futures`. The
/// FLOE framing and one-per-file key schedule stay in floe-rs (see the module
/// docs); only this per-segment primitive crosses into JavaScript. Software AES
/// compiled to WASM is roughly two orders of magnitude slower, so this backend
/// is what makes multi-gigabyte files viable on the web.
///
/// [SubtleCrypto]: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
#[cfg(target_family = "wasm")]
#[derive(Clone, Copy, Debug, Default)]
pub struct WebCryptoAeadBackend;

#[cfg(target_family = "wasm")]
mod webcrypto {
    use js_sys::{Array, Object, Reflect, Uint8Array};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Crypto, CryptoKey, SubtleCrypto};

    use super::{FloeAeadBackend, FloeAsyncError, WebCryptoAeadBackend};

    /// Map a rejected Web Crypto `JsValue` onto an [`FloeAsyncError::Aead`].
    fn aead_err(context: &'static str) -> impl Fn(JsValue) -> FloeAsyncError {
        move |value| FloeAsyncError::Aead(format!("{context}: {value:?}"))
    }

    /// The global `crypto.subtle` object.
    fn subtle() -> Result<SubtleCrypto, FloeAsyncError> {
        let crypto = Reflect::get(&js_sys::global(), &JsValue::from_str("crypto"))
            .and_then(|value| value.dyn_into::<Crypto>())
            .map_err(aead_err("the `crypto` global is unavailable"))?;
        Ok(crypto.subtle())
    }

    /// Build the `{ name, iv, additionalData, tagLength }` AES-GCM parameters.
    fn aes_gcm_params(nonce: &[u8], associated_data: &[u8]) -> Result<Object, FloeAsyncError> {
        let algorithm = Object::new();
        let set = |key: &str, value: &JsValue| {
            Reflect::set(&algorithm, &JsValue::from_str(key), value)
                .map(|_| ())
                .map_err(aead_err("building the AES-GCM parameters"))
        };
        set("name", &JsValue::from_str("AES-GCM"))?;
        set("iv", &Uint8Array::from(nonce))?;
        set("additionalData", &Uint8Array::from(associated_data))?;
        set("tagLength", &JsValue::from_f64(128.0))?;
        Ok(algorithm)
    }

    impl FloeAeadBackend for WebCryptoAeadBackend {
        type PreparedKey = CryptoKey;
        type Error = FloeAsyncError;

        async fn import_key(&self, key: &[u8]) -> Result<CryptoKey, FloeAsyncError> {
            let usages = Array::new();
            usages.push(&JsValue::from_str("encrypt"));
            usages.push(&JsValue::from_str("decrypt"));

            let promise = subtle()?
                .import_key_with_str("raw", &Uint8Array::from(key), "AES-GCM", false, &usages)
                .map_err(aead_err("importKey"))?;
            JsFuture::from(promise)
                .await
                .map_err(aead_err("importKey"))?
                .dyn_into::<CryptoKey>()
                .map_err(aead_err("importKey returned a non-CryptoKey"))
        }

        async fn seal(
            &self,
            key: &CryptoKey,
            nonce: &[u8],
            associated_data: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, FloeAsyncError> {
            let params = aes_gcm_params(nonce, associated_data)?;
            let promise = subtle()?
                .encrypt_with_object_and_buffer_source(&params, key, &Uint8Array::from(plaintext))
                .map_err(aead_err("encrypt"))?;
            let result = JsFuture::from(promise).await.map_err(aead_err("encrypt"))?;
            Ok(Uint8Array::new(&result).to_vec())
        }

        async fn open(
            &self,
            key: &CryptoKey,
            nonce: &[u8],
            associated_data: &[u8],
            ciphertext_and_tag: &[u8],
        ) -> Result<Vec<u8>, FloeAsyncError> {
            let params = aes_gcm_params(nonce, associated_data)?;
            let promise = subtle()?
                .decrypt_with_object_and_buffer_source(
                    &params,
                    key,
                    &Uint8Array::from(ciphertext_and_tag),
                )
                .map_err(aead_err("decrypt"))?;
            // A rejected promise here is an authentication failure (a bad tag).
            let result =
                JsFuture::from(promise).await.map_err(aead_err("decrypt (authentication)"))?;
            Ok(Uint8Array::new(&result).to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit, Payload},
    };
    use floe_rs::gcm::{FloeDecryptor, FloeKey, Header, Segment};
    use futures_executor::block_on;
    use ruma::{MxcUri, OwnedMxcUri};

    use super::{
        ENC_SEG_LEN, FLOE_HEADER_LEN, FLOE_V0_PLAINTEXT_SEG_LEN, FloeAeadBackend,
        FloeAsyncDecryptor, FloeAsyncEncryptor, FloeAsyncError, KEY_SIZE,
    };

    /// The associated data the canonical FLOE test vectors were generated with.
    const KAT_AAD: &[u8] = b"This is AAD";
    /// `CUSTOM_ROTATION_MASK` from the floe-rs vector suite (the u64 bits of
    /// `-4i64`), which rotates the DEK every four segments.
    const CUSTOM_ROTATION_MASK: u64 = u64::from_be_bytes((-4i64).to_be_bytes());

    /// A synchronous RustCrypto AES-256-GCM implementation of the async seam.
    ///
    /// Its methods complete immediately, standing in for the web build's
    /// awaited `crypto.subtle` backend so the async driver — and this
    /// module's wrappers around it — can be exercised natively.
    struct RustCryptoAeadBackend;

    impl FloeAeadBackend for RustCryptoAeadBackend {
        type PreparedKey = Aes256Gcm;
        type Error = FloeAsyncError;

        async fn import_key(&self, key: &[u8]) -> Result<Aes256Gcm, FloeAsyncError> {
            Aes256Gcm::new_from_slice(key)
                .map_err(|_| FloeAsyncError::Aead("invalid AES-256 key length".to_owned()))
        }

        async fn seal(
            &self,
            key: &Aes256Gcm,
            nonce: &[u8],
            associated_data: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, FloeAsyncError> {
            let gcm_nonce =
                Nonce::try_from(nonce).map_err(|_| FloeAsyncError::Aead("bad nonce".to_owned()))?;
            key.encrypt(&gcm_nonce, Payload { msg: plaintext, aad: associated_data })
                .map_err(|_| FloeAsyncError::Aead("AES-256-GCM seal failed".to_owned()))
        }

        async fn open(
            &self,
            key: &Aes256Gcm,
            nonce: &[u8],
            associated_data: &[u8],
            ciphertext_and_tag: &[u8],
        ) -> Result<Vec<u8>, FloeAsyncError> {
            let gcm_nonce =
                Nonce::try_from(nonce).map_err(|_| FloeAsyncError::Aead("bad nonce".to_owned()))?;
            key.decrypt(&gcm_nonce, Payload { msg: ciphertext_and_tag, aad: associated_data })
                .map_err(|_| {
                    FloeAsyncError::Aead("AES-256-GCM open failed (authentication)".to_owned())
                })
        }
    }

    fn mxc(uri: &str) -> OwnedMxcUri {
        OwnedMxcUri::from(uri)
    }

    /// The bits of the file block the tests need, extracted before the
    /// (droppable, key-zeroizing) encryptor goes away.
    struct FloeEncryptedFileKey {
        key: [u8; KEY_SIZE],
        size: u64,
        v: String,
    }

    /// Encrypt `plaintext` end to end through the async encryptor, returning
    /// the full blob and the file block. Chunks the plaintext at the
    /// segment size and marks the last chunk final.
    fn encrypt_all<const S: u32>(
        url: &MxcUri,
        plaintext: &[u8],
    ) -> (Vec<u8>, FloeEncryptedFileKey) {
        let mut encryptor = FloeAsyncEncryptor::<_, S>::new(RustCryptoAeadBackend, url);
        let mut blob = encryptor.header().to_vec();

        let pt_per_seg = S as usize - Segment::<S>::overhead();
        let chunks: Vec<&[u8]> = if plaintext.is_empty() {
            vec![&[][..]]
        } else {
            plaintext.chunks(pt_per_seg).collect()
        };
        let last = chunks.len() - 1;
        for (i, chunk) in chunks.iter().enumerate() {
            let frame =
                block_on(encryptor.encrypt_segment(chunk, i == last)).expect("encrypt segment");
            blob.extend_from_slice(&frame);
        }

        let file = encryptor.finish();
        (blob, FloeEncryptedFileKey { key: *file.key.k.as_inner(), size: file.size, v: file.v })
    }

    /// Decrypt a whole blob through the async decryptor at segment size `S`.
    fn decrypt_all<const S: u32>(
        blob: &[u8],
        key: &[u8; KEY_SIZE],
        associated_data: &[u8],
        rotation_mask: Option<u64>,
    ) -> Result<Vec<u8>, FloeAsyncError> {
        let header = &blob[..FLOE_HEADER_LEN];
        let mut decryptor = match rotation_mask {
            Some(mask) => FloeAsyncDecryptor::<_, S>::new_with_rotation_mask(
                RustCryptoAeadBackend,
                header,
                key,
                associated_data,
                mask,
            )?,
            None => FloeAsyncDecryptor::<_, S>::new(
                RustCryptoAeadBackend,
                header,
                key,
                associated_data,
            )?,
        };

        let mut out = Vec::new();
        for chunk in blob[FLOE_HEADER_LEN..].chunks(S as usize) {
            let plaintext = block_on(decryptor.decrypt_segment(chunk))?;
            out.extend_from_slice(&plaintext);
        }
        Ok(out)
    }

    /// Decrypt a blob with the canonical `floe-rs` synchronous decryptor — an
    /// independent oracle. Success proves the async path's framing and every
    /// derived key match the reference construction.
    fn floers_decrypt<const S: u32>(
        blob: &[u8],
        key: &[u8; KEY_SIZE],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, String> {
        let floe_key = FloeKey::from(*key);
        let header =
            Header::from_bytes(&blob[..Header::LENGTH]).map_err(|e| format!("header: {e}"))?;
        let decryptor = FloeDecryptor::<S>::new(&floe_key, associated_data, &header)
            .map_err(|e| format!("decryptor: {e:?}"))?;

        let body = &blob[Header::LENGTH..];
        let chunks: Vec<&[u8]> = body.chunks(S as usize).collect();
        let last = chunks.len() - 1;
        let mut out = Vec::new();
        let mut buffer = vec![0u8; decryptor.plaintext_size()];
        for (i, raw) in chunks.iter().enumerate() {
            let segment = Segment::<S>::from_bytes(raw, i == last)
                .map_err(|e| format!("segment {i}: {e:?}"))?;
            let plaintext = &mut buffer[..segment.plaintext_size()];
            decryptor
                .decrypt_segment(&segment, plaintext, i as u64)
                .map_err(|e| format!("decrypt {i}: {e:?}"))?;
            out.extend_from_slice(plaintext);
        }
        Ok(out)
    }

    /// Decrypt a canonical FLOE KAT *through the async decryptor* and assert it
    /// matches the expected plaintext. Decrypting a foreign fixed ciphertext
    /// can only succeed if the framing and every HKDF-derived key are byte
    /// identical to the reference construction.
    fn decrypt_kat<const S: u32>(ct_hex: &str, pt_hex: &str, rotation_mask: Option<u64>) {
        let ciphertext = hex::decode(ct_hex.trim()).expect("ct hex");
        let plaintext = hex::decode(pt_hex.trim()).expect("pt hex");
        let key = [0u8; KEY_SIZE];

        let decrypted =
            decrypt_all::<S>(&ciphertext, &key, KAT_AAD, rotation_mask).expect("decrypt");
        assert_eq!(plaintext, decrypted, "decrypted KAT mismatch");
    }

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

    /// A multi-segment blob round-trips through the async encryptor/decryptor
    /// at 256 KiB, and the canonical `floe-rs` decryptor accepts it (byte
    /// compat).
    #[test]
    fn async_roundtrip_and_floers_crossdecrypt() {
        let url = mxc("mxc://verji.example/abc123");
        let pt_per_seg = FLOE_V0_PLAINTEXT_SEG_LEN;

        // A partial final segment, an exact segment multiple (full final), and empty.
        let sizes = [pt_per_seg * 2 + 50_000, pt_per_seg * 3, 0];
        for size in sizes {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

            let (blob, file) = encrypt_all::<ENC_SEG_LEN>(&url, &plaintext);
            assert_eq!(file.v, super::FLOE_V0);
            assert_eq!(file.size, plaintext.len() as u64);

            let self_decrypted = decrypt_all::<ENC_SEG_LEN>(&blob, &file.key, url.as_bytes(), None)
                .expect("async self round-trip");
            assert_eq!(self_decrypted, plaintext, "async round-trip mismatch (size {size})");

            let floers_decrypted = floers_decrypt::<ENC_SEG_LEN>(&blob, &file.key, url.as_bytes())
                .expect("floe-rs cross-decrypt");
            assert_eq!(floers_decrypted, plaintext, "floe-rs cross-decrypt mismatch (size {size})");
        }
    }

    /// A non-final segment frame is exactly `ENC_SEG_LEN` bytes.
    #[test]
    fn non_final_segment_is_full_size() {
        let url = mxc("mxc://verji.example/multiseg");
        let pt_per_seg = FLOE_V0_PLAINTEXT_SEG_LEN;
        let plaintext: Vec<u8> = (0..(pt_per_seg * 2 + 10)).map(|i| (i % 251) as u8).collect();

        let (blob, _) = encrypt_all::<ENC_SEG_LEN>(&url, &plaintext);
        assert_eq!(
            &blob[FLOE_HEADER_LEN..FLOE_HEADER_LEN + 4],
            &[0xFF, 0xFF, 0xFF, 0xFF],
            "the first segment must be framed as non-final"
        );
        assert!(blob.len() > FLOE_HEADER_LEN + ENC_SEG_LEN as usize, "expected multiple segments");
    }

    /// The mxc `url` is bound in, so decrypting under a different `url` fails
    /// the header tag at construction.
    #[test]
    fn wrong_url_aad_fails_header_tag() {
        let url = mxc("mxc://verji.example/abc123");
        let (blob, file) = encrypt_all::<ENC_SEG_LEN>(&url, b"hello world");

        let wrong = mxc("mxc://verji.example/DIFFERENT");
        let result = decrypt_all::<ENC_SEG_LEN>(&blob, &file.key, wrong.as_bytes(), None);
        assert!(
            matches!(result, Err(FloeAsyncError::HeaderTag)),
            "a wrong url-AAD must fail the header tag, got {result:?}"
        );
    }

    /// A tampered segment fails authentication at the AEAD backend.
    #[test]
    fn tampered_segment_fails_authentication() {
        let url = mxc("mxc://verji.example/tamper");
        let (mut blob, file) = encrypt_all::<ENC_SEG_LEN>(&url, b"authentic bytes");

        // Flip a ciphertext byte in the (single, final) segment.
        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        let result = decrypt_all::<ENC_SEG_LEN>(&blob, &file.key, url.as_bytes(), None);
        assert!(
            matches!(result, Err(FloeAsyncError::Aead(_))),
            "a tampered segment must fail authentication, got {result:?}"
        );
    }
}

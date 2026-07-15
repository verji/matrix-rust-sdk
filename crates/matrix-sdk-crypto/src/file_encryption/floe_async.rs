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

//! Async, hardware-accelerated FLOE encryption for the web target.
//!
//! This is the `async` sibling of the synchronous streaming FLOE adapter in
//! [`super::floe`]. Both produce and consume the exact same on-the-wire blob
//! (the [`super::floe`] module documents its layout), and both are selected by
//! the same `v` discriminator; they differ only in *where the per-segment AEAD
//! runs*.
//!
//! The synchronous adapter drives [`floe-rs`], whose AEAD is a synchronous
//! RustCrypto primitive. That is correct on native targets with hardware AES,
//! but on the web the only hardware-accelerated AES-GCM is
//! [`crypto.subtle`][SubtleCrypto], which is **asynchronous** — a synchronous
//! segment loop can't await it. Software AES compiled to WASM is ~100× slower
//! and can't move multi-gigabyte files.
//!
//! So this module keeps FLOE's framing and its one-per-file HKDF-SHA-384 key
//! schedule in synchronous Rust — byte-for-byte the same construction as
//! [`floe-rs`], re-implemented here because those internals aren't public — and
//! moves *only* the per-segment AES-256-GCM primitive behind an injectable,
//! `async` seam ([`FloeAeadBackend`]). The web build wires a `crypto.subtle`
//! backend into that seam; the seam stays injectable so a browser-native JSPI
//! backend (which would let the primitive be synchronous again) can replace it
//! later without touching the driver.
//!
//! The segment framing, header, and key schedule implemented here are verified
//! byte-identical to the canonical construction in this module's tests: the
//! shared cross-implementation FLOE test vectors decrypt through
//! [`FloeAsyncDecryptor`], and blobs produced by [`FloeAsyncEncryptor`] decrypt
//! through the canonical [`floe-rs`] decryptor.
//!
//! [FLOE]: https://github.com/Snowflake-Labs/floe-specification
//! [`floe-rs`]: floe_rs
//! [SubtleCrypto]: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto

use std::fmt;

use hkdf::Hkdf;
use rand::{Rng, rng};
use ruma::{MxcUri, OwnedMxcUri};
use sha2::Sha384;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;

use super::floe::{ENC_SEG_LEN, FLOE_V0, FloeEncryptedFile, floe_jwk};

/// The size of the FLOE root key (AES-256).
const KEY_SIZE: usize = 32;
/// The length of the FLOE IV carried in the header, in bytes.
const FLOE_IV_LEN: usize = 32;
/// The length of the fixed parameter block at the front of the header.
const PARAMS_LEN: usize = 10;
/// The length of the key-committing header tag, in bytes.
const HEADER_TAG_LEN: usize = 32;
/// The total FLOE header length: parameters ‖ IV ‖ header tag.
const HEADER_LEN: usize = PARAMS_LEN + FLOE_IV_LEN + HEADER_TAG_LEN;
/// The AES-256-GCM nonce length.
const NONCE_LEN: usize = 12;
/// The AES-256-GCM tag length.
const TAG_LEN: usize = 16;
/// The length of the per-segment framing marker, in bytes.
const SEG_MARKER_LEN: usize = 4;
/// Per-segment framing overhead: marker ‖ nonce ‖ tag.
const SEG_OVERHEAD: usize = SEG_MARKER_LEN + NONCE_LEN + TAG_LEN;
/// The framing marker that flags any non-final segment.
const NON_FINAL_MARKER: u32 = u32::MAX;
/// The KDF output size (SHA-384), which is also the FLOE message-key length.
const MESSAGE_KEY_LEN: usize = 48;
/// The per-segment associated-data length: segment number ‖ is-final flag.
const SEGMENT_AAD_LEN: usize = 9;
/// The AEAD identifier for AES-256-GCM in the FLOE parameter block.
const AEAD_ID_GCM: u8 = 0;
/// The KDF identifier for HMAC-SHA-384 in the FLOE parameter block.
const KDF_ID_SHA384: u8 = 0;
/// The default AEAD rotation mask: a fresh DEK every 2²⁰ segments (256 GB at
/// [`ENC_SEG_LEN`]), so every file below that lives under a single DEK.
const DEFAULT_ROTATION_MASK: u64 = !((1u64 << 20) - 1);

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

/// A pluggable, `async` AES-256-GCM backend — the seam the async FLOE driver
/// delegates its per-segment AEAD to.
///
/// FLOE's framing and its one-per-file HKDF stay in the driver (synchronous
/// Rust); only the AES-256-GCM of each ≤256 KiB segment crosses this seam. The
/// web build implements it over [`crypto.subtle`][SubtleCrypto] (whose
/// operations genuinely await); tests implement it synchronously over
/// RustCrypto. Keeping it injectable lets a future browser-native JSPI backend
/// swap in without changing the driver.
///
/// [SubtleCrypto]: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
// The seam is intentionally used from single-threaded WASM where the backing
// futures (`crypto.subtle`) are `!Send`, so the driver never adds `Send`
// bounds; `async fn` in the trait is exactly the desired desugaring.
#[allow(async_fn_in_trait)]
pub trait FloeAeadBackend {
    /// A handle to an imported AES-256-GCM key.
    ///
    /// Imported once per DEK epoch (once per file for any file below the
    /// rotation boundary) and reused for every segment in that epoch, matching
    /// WebCrypto's `importKey`-once cost model.
    type Key;

    /// Import a raw 32-byte AES-256-GCM key into a reusable [`Key`] handle.
    ///
    /// [`Key`]: Self::Key
    async fn import_key(&self, key: &[u8; KEY_SIZE]) -> Result<Self::Key, FloeAsyncError>;

    /// Seal one segment, returning `ciphertext ‖ tag` (the 16-byte GCM tag
    /// appended to the ciphertext).
    async fn seal(
        &self,
        key: &Self::Key,
        nonce: &[u8; NONCE_LEN],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, FloeAsyncError>;

    /// Open one segment. `ciphertext_and_tag` is `ciphertext ‖ tag`; returns
    /// the plaintext, or [`FloeAsyncError::Aead`] on an authentication
    /// failure.
    async fn open(
        &self,
        key: &Self::Key,
        nonce: &[u8; NONCE_LEN],
        associated_data: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, FloeAsyncError>;
}

// ---------------------------------------------------------------------------
// FLOE framing + key schedule — synchronous Rust, byte-faithful to floe-rs.
// ---------------------------------------------------------------------------

/// `PARAM_ENCODE`: the 10 fixed header bytes — `aead_id ‖ kdf_id ‖
/// segment_length(u32 BE) ‖ floe_iv_size(u32 BE)`.
fn params_bytes(seg_size: u32) -> [u8; PARAMS_LEN] {
    let mut params = [0u8; PARAMS_LEN];
    params[0] = AEAD_ID_GCM;
    params[1] = KDF_ID_SHA384;
    params[2..6].copy_from_slice(&seg_size.to_be_bytes());
    params[6..10].copy_from_slice(&(FLOE_IV_LEN as u32).to_be_bytes());
    params
}

/// `FLOE_KDF`: HKDF-Expand (no extract) with SHA-384 and
/// `info = params ‖ floe_iv ‖ purpose ‖ associated_data`. `prk` must be at
/// least the SHA-384 output size (48 bytes).
fn floe_kdf(
    prk: &[u8],
    floe_iv: &[u8; FLOE_IV_LEN],
    associated_data: &[u8],
    purpose: &[u8],
    seg_size: u32,
    output: &mut [u8],
) {
    let params = params_bytes(seg_size);
    let hkdf = Hkdf::<Sha384>::from_prk(prk)
        .expect("the FLOE pseudo-random key is at least the SHA-384 output size");
    hkdf.expand_multi_info(&[&params, floe_iv, purpose, associated_data], output)
        .expect("the requested FLOE key-material length is within HKDF-Expand limits");
}

/// Zero-pad the 32-byte FLOE key to the 48-byte SHA-384 output size, the way
/// `floe-rs` feeds `Hkdf::from_prk` (mirroring HMAC's short-key zero padding).
fn padded_prk(key: &[u8; KEY_SIZE]) -> [u8; MESSAGE_KEY_LEN] {
    let mut prk = [0u8; MESSAGE_KEY_LEN];
    prk[..KEY_SIZE].copy_from_slice(key);
    prk
}

/// `HeaderTag = FLOE_KDF(key, iv, aad, "HEADER_TAG:", 32)`.
fn derive_header_tag(
    key: &[u8; KEY_SIZE],
    floe_iv: &[u8; FLOE_IV_LEN],
    associated_data: &[u8],
    seg_size: u32,
) -> [u8; HEADER_TAG_LEN] {
    let mut prk = padded_prk(key);
    let mut tag = [0u8; HEADER_TAG_LEN];
    floe_kdf(&prk, floe_iv, associated_data, b"HEADER_TAG:", seg_size, &mut tag);
    prk.zeroize();
    tag
}

/// `MessageKey = FLOE_KDF(key, iv, aad, "MESSAGE_KEY:", 48)`.
fn derive_message_key(
    key: &[u8; KEY_SIZE],
    floe_iv: &[u8; FLOE_IV_LEN],
    associated_data: &[u8],
    seg_size: u32,
) -> [u8; MESSAGE_KEY_LEN] {
    let mut prk = padded_prk(key);
    let mut message_key = [0u8; MESSAGE_KEY_LEN];
    floe_kdf(&prk, floe_iv, associated_data, b"MESSAGE_KEY:", seg_size, &mut message_key);
    prk.zeroize();
    message_key
}

/// `DEK = FLOE_KDF(message_key, iv, aad, "DEK:" ‖ I2BE(segment & mask, 8),
/// 32)`.
fn derive_epoch_key(
    message_key: &[u8; MESSAGE_KEY_LEN],
    floe_iv: &[u8; FLOE_IV_LEN],
    associated_data: &[u8],
    segment_number: u64,
    rotation_mask: u64,
    seg_size: u32,
) -> [u8; KEY_SIZE] {
    let masked_counter = segment_number & rotation_mask;
    let mut purpose = [0u8; 12];
    purpose[..4].copy_from_slice(b"DEK:");
    purpose[4..].copy_from_slice(&masked_counter.to_be_bytes());

    let mut epoch_key = [0u8; KEY_SIZE];
    floe_kdf(message_key, floe_iv, associated_data, &purpose, seg_size, &mut epoch_key);
    epoch_key
}

/// The per-segment AEAD associated data: `I2BE(segment_number, 8) ‖ is_final`.
/// This is distinct from the user's associated data (the mxc `url`), which is
/// bound through the HKDF, not here.
fn segment_associated_data(segment_number: u64, is_final: bool) -> [u8; SEGMENT_AAD_LEN] {
    let mut aad = [0u8; SEGMENT_AAD_LEN];
    aad[..8].copy_from_slice(&segment_number.to_be_bytes());
    aad[8] = is_final as u8;
    aad
}

/// The 4-byte segment framing marker: `u32::MAX` for a non-final segment, else
/// the total encrypted length of the (final) segment.
fn framing_marker(plaintext_len: usize, is_final: bool) -> u32 {
    if is_final { (plaintext_len + SEG_OVERHEAD) as u32 } else { NON_FINAL_MARKER }
}

/// The current DEK epoch: the masked segment counter and its imported key.
type Epoch<K> = (u64, K);

/// The per-file FLOE key-derivation context: everything needed to derive a
/// segment's DEK. Shared by the encryptor and decryptor so the derivation and
/// its epoch-rotation logic live in one place.
struct KeySchedule {
    message_key: [u8; MESSAGE_KEY_LEN],
    floe_iv: [u8; FLOE_IV_LEN],
    associated_data: Vec<u8>,
    rotation_mask: u64,
}

impl KeySchedule {
    /// Import the DEK for `segment_number` into `epoch`, reusing the cached key
    /// unless the segment crossed into a new rotation epoch.
    async fn ensure_epoch<B: FloeAeadBackend>(
        &self,
        backend: &B,
        epoch: &mut Option<Epoch<B::Key>>,
        seg_size: u32,
        segment_number: u64,
    ) -> Result<(), FloeAsyncError> {
        let masked_counter = segment_number & self.rotation_mask;
        if epoch.as_ref().map(|(counter, _)| *counter) != Some(masked_counter) {
            let mut dek = derive_epoch_key(
                &self.message_key,
                &self.floe_iv,
                &self.associated_data,
                segment_number,
                self.rotation_mask,
                seg_size,
            );
            let key = backend.import_key(&dek).await?;
            dek.zeroize();
            *epoch = Some((masked_counter, key));
        }
        Ok(())
    }
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        self.message_key.zeroize();
    }
}

// ---------------------------------------------------------------------------
// The async FLOE encryptor.
// ---------------------------------------------------------------------------

/// Encrypts a plaintext into the streaming FLOE blob one segment at a time,
/// delegating each segment's AES-256-GCM to an [`FloeAeadBackend`].
///
/// Call [`header`](Self::header) once, then [`encrypt_segment`] per plaintext
/// chunk (the caller decides which chunk is final, e.g. by reading one chunk
/// ahead), concatenating the header and every returned frame into the blob.
/// After the final segment, [`finish`](Self::finish) returns the
/// [`FloeEncryptedFile`] block (carrying the fresh root key and plaintext size)
/// for the room-encrypted event.
///
/// A plaintext chunk must be at most `S - `[`SEG_OVERHEAD`] bytes; every
/// non-final chunk should be exactly that size so its frame is exactly `S`
/// bytes. `S` is the encrypted-segment size and defaults to [`ENC_SEG_LEN`].
///
/// [`encrypt_segment`]: Self::encrypt_segment
pub struct FloeAsyncEncryptor<B: FloeAeadBackend, const S: u32 = ENC_SEG_LEN> {
    backend: B,
    root_key: [u8; KEY_SIZE],
    schedule: KeySchedule,
    url: OwnedMxcUri,
    header: Vec<u8>,
    plaintext_len: u64,
    next_segment_number: u64,
    epoch: Option<Epoch<B::Key>>,
}

#[cfg(not(tarpaulin_include))]
impl<B: FloeAeadBackend, const S: u32> fmt::Debug for FloeAsyncEncryptor<B, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FloeAsyncEncryptor")
            .field("url", &self.url)
            .field("next_segment_number", &self.next_segment_number)
            .field("plaintext_len", &self.plaintext_len)
            .finish_non_exhaustive()
    }
}

impl<B: FloeAeadBackend, const S: u32> FloeAsyncEncryptor<B, S> {
    /// Start encrypting under a fresh random root key, with `url` bound as the
    /// FLOE associated data and the default AEAD rotation.
    ///
    /// # Panics
    ///
    /// Panics if the system RNG can't provide enough randomness for the root
    /// key or the FLOE IV.
    pub fn new(backend: B, url: &MxcUri) -> Self {
        Self::new_with_rotation_mask(backend, url, DEFAULT_ROTATION_MASK)
    }

    /// Like [`new`](Self::new) but with an explicit AEAD rotation mask.
    ///
    /// [`FLOE_V0`] uses the default rotation, so this is only needed to match
    /// the cross-implementation rotation test vectors.
    ///
    /// # Panics
    ///
    /// As for [`new`](Self::new).
    pub fn new_with_rotation_mask(backend: B, url: &MxcUri, rotation_mask: u64) -> Self {
        let mut root_key = [0u8; KEY_SIZE];
        let mut floe_iv = [0u8; FLOE_IV_LEN];
        rng().fill_bytes(&mut root_key);
        rng().fill_bytes(&mut floe_iv);

        let associated_data = url.as_bytes().to_vec();
        let header_tag = derive_header_tag(&root_key, &floe_iv, &associated_data, S);
        let message_key = derive_message_key(&root_key, &floe_iv, &associated_data, S);

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&params_bytes(S));
        header.extend_from_slice(&floe_iv);
        header.extend_from_slice(&header_tag);

        Self {
            backend,
            root_key,
            schedule: KeySchedule { message_key, floe_iv, associated_data, rotation_mask },
            url: url.to_owned(),
            header,
            plaintext_len: 0,
            next_segment_number: 0,
            epoch: None,
        }
    }

    /// The 74-byte FLOE header, ready before any segment is encrypted. It must
    /// be the first bytes of the blob.
    pub fn header(&self) -> &[u8] {
        &self.header
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
    /// segment (including importing the epoch key).
    pub async fn encrypt_segment(
        &mut self,
        plaintext: &[u8],
        is_final: bool,
    ) -> Result<Vec<u8>, FloeAsyncError> {
        let segment_number = self.next_segment_number;
        self.schedule.ensure_epoch(&self.backend, &mut self.epoch, S, segment_number).await?;

        let mut nonce = [0u8; NONCE_LEN];
        rng().fill_bytes(&mut nonce);
        let aad = segment_associated_data(segment_number, is_final);

        let key = &self.epoch.as_ref().expect("the epoch key was imported above").1;
        let ciphertext_and_tag = self.backend.seal(key, &nonce, &aad, plaintext).await?;

        let marker = framing_marker(plaintext.len(), is_final);
        let mut frame = Vec::with_capacity(SEG_MARKER_LEN + NONCE_LEN + ciphertext_and_tag.len());
        frame.extend_from_slice(&marker.to_be_bytes());
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ciphertext_and_tag);

        self.plaintext_len += plaintext.len() as u64;
        self.next_segment_number += 1;
        Ok(frame)
    }

    /// Produce the FLOE file block for the room-encrypted event, with `size`
    /// reflecting the plaintext encrypted so far. Call it after the final
    /// segment; it borrows rather than consumes, so the root key is zeroized
    /// only when the encryptor is dropped.
    pub fn finish(&self) -> FloeEncryptedFile {
        FloeEncryptedFile {
            url: self.url.clone(),
            v: FLOE_V0.to_owned(),
            key: floe_jwk(&self.root_key),
            enc_seg_len: S,
            size: self.plaintext_len,
        }
    }
}

impl<B: FloeAeadBackend, const S: u32> Drop for FloeAsyncEncryptor<B, S> {
    fn drop(&mut self) {
        // The message key is zeroized by `KeySchedule`'s own `Drop`.
        self.root_key.zeroize();
    }
}

// ---------------------------------------------------------------------------
// The async FLOE decryptor.
// ---------------------------------------------------------------------------

/// Decrypts a streaming FLOE blob one segment at a time, delegating each
/// segment's AES-256-GCM to an [`FloeAeadBackend`].
///
/// Construct it from the 74-byte header (which is validated against the key and
/// associated data), then feed each `S`-sized encrypted segment frame from the
/// blob body to [`decrypt_segment`](Self::decrypt_segment) in order. Each
/// segment's marker tells the decryptor whether it is the final one, so a
/// truncated stream (a missing final segment) never silently succeeds.
///
/// `S` is the encrypted-segment size and defaults to [`ENC_SEG_LEN`].
pub struct FloeAsyncDecryptor<B: FloeAeadBackend, const S: u32 = ENC_SEG_LEN> {
    backend: B,
    schedule: KeySchedule,
    next_segment_number: u64,
    epoch: Option<Epoch<B::Key>>,
    done: bool,
}

#[cfg(not(tarpaulin_include))]
impl<B: FloeAeadBackend, const S: u32> fmt::Debug for FloeAsyncDecryptor<B, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FloeAsyncDecryptor")
            .field("next_segment_number", &self.next_segment_number)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<B: FloeAeadBackend, const S: u32> FloeAsyncDecryptor<B, S> {
    /// Build a decryptor from the blob's 74-byte header, validating it against
    /// `key` and `associated_data` (the mxc `url`) under the default rotation.
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
        associated_data: &[u8],
    ) -> Result<Self, FloeAsyncError> {
        Self::new_with_rotation_mask(backend, header, key, associated_data, DEFAULT_ROTATION_MASK)
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
        associated_data: &[u8],
        rotation_mask: u64,
    ) -> Result<Self, FloeAsyncError> {
        if header.len() < HEADER_LEN {
            return Err(FloeAsyncError::Malformed("the FLOE header is shorter than 74 bytes"));
        }

        let mut floe_iv = [0u8; FLOE_IV_LEN];
        floe_iv.copy_from_slice(&header[PARAMS_LEN..PARAMS_LEN + FLOE_IV_LEN]);
        let stored_tag = &header[PARAMS_LEN + FLOE_IV_LEN..HEADER_LEN];

        // The parameters (segment size, IV size, algorithm ids) are authenticated
        // implicitly: the tag is re-derived from `S` and this module's fixed ids,
        // so a blob framed with different parameters fails right here.
        let expected_tag = derive_header_tag(key, &floe_iv, associated_data, S);
        if !bool::from(expected_tag.as_slice().ct_eq(stored_tag)) {
            return Err(FloeAsyncError::HeaderTag);
        }

        let message_key = derive_message_key(key, &floe_iv, associated_data, S);

        Ok(Self {
            backend,
            schedule: KeySchedule {
                message_key,
                floe_iv,
                associated_data: associated_data.to_vec(),
                rotation_mask,
            },
            next_segment_number: 0,
            epoch: None,
            done: false,
        })
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
        if self.done {
            return Err(FloeAsyncError::Malformed(
                "a FLOE segment was supplied after the final one",
            ));
        }
        if frame.len() < SEG_OVERHEAD {
            return Err(FloeAsyncError::Malformed(
                "the FLOE segment is shorter than the framing overhead",
            ));
        }

        let marker = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        let is_final = marker != NON_FINAL_MARKER;
        if is_final {
            if marker as usize != frame.len() || frame.len() > S as usize {
                return Err(FloeAsyncError::Malformed("the final FLOE segment length is invalid"));
            }
        } else if frame.len() != S as usize {
            return Err(FloeAsyncError::Malformed(
                "a non-final FLOE segment is not the full segment size",
            ));
        }

        let segment_number = self.next_segment_number;
        self.schedule.ensure_epoch(&self.backend, &mut self.epoch, S, segment_number).await?;

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&frame[SEG_MARKER_LEN..SEG_MARKER_LEN + NONCE_LEN]);
        let ciphertext_and_tag = &frame[SEG_MARKER_LEN + NONCE_LEN..];
        let aad = segment_associated_data(segment_number, is_final);

        let key = &self.epoch.as_ref().expect("the epoch key was imported above").1;
        let plaintext = self.backend.open(key, &nonce, &aad, ciphertext_and_tag).await?;

        self.next_segment_number += 1;
        if is_final {
            self.done = true;
        }
        Ok(plaintext)
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
    use ruma::OwnedMxcUri;

    use super::{
        ENC_SEG_LEN, FloeAeadBackend, FloeAsyncDecryptor, FloeAsyncEncryptor, FloeAsyncError,
        HEADER_LEN, KEY_SIZE, NONCE_LEN, SEG_OVERHEAD,
    };

    /// The associated data the canonical FLOE test vectors were generated with.
    const KAT_AAD: &[u8] = b"This is AAD";
    /// `CUSTOM_ROTATION_MASK` from the floe-rs vector suite (the u64 bits of
    /// `-4i64`), which rotates the DEK every four segments.
    const CUSTOM_ROTATION_MASK: u64 = u64::from_be_bytes((-4i64).to_be_bytes());

    /// A synchronous RustCrypto AES-256-GCM implementation of the async seam.
    ///
    /// Its methods complete immediately, standing in for the web build's
    /// awaited `crypto.subtle` backend so the async driver — its framing, key
    /// schedule, epoch rotation and error paths — can be exercised natively.
    struct RustCryptoAeadBackend;

    impl FloeAeadBackend for RustCryptoAeadBackend {
        type Key = Aes256Gcm;

        async fn import_key(&self, key: &[u8; KEY_SIZE]) -> Result<Aes256Gcm, FloeAsyncError> {
            Aes256Gcm::new_from_slice(key)
                .map_err(|_| FloeAsyncError::Aead("invalid AES-256 key length".to_owned()))
        }

        async fn seal(
            &self,
            key: &Aes256Gcm,
            nonce: &[u8; NONCE_LEN],
            associated_data: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, FloeAsyncError> {
            let gcm_nonce = Nonce::try_from(nonce.as_slice()).expect("the FLOE nonce is 12 bytes");
            key.encrypt(&gcm_nonce, Payload { msg: plaintext, aad: associated_data })
                .map_err(|_| FloeAsyncError::Aead("AES-256-GCM seal failed".to_owned()))
        }

        async fn open(
            &self,
            key: &Aes256Gcm,
            nonce: &[u8; NONCE_LEN],
            associated_data: &[u8],
            ciphertext_and_tag: &[u8],
        ) -> Result<Vec<u8>, FloeAsyncError> {
            let gcm_nonce = Nonce::try_from(nonce.as_slice()).expect("the FLOE nonce is 12 bytes");
            key.decrypt(&gcm_nonce, Payload { msg: ciphertext_and_tag, aad: associated_data })
                .map_err(|_| {
                    FloeAsyncError::Aead("AES-256-GCM open failed (authentication)".to_owned())
                })
        }
    }

    fn mxc(uri: &str) -> OwnedMxcUri {
        OwnedMxcUri::from(uri)
    }

    /// Encrypt `plaintext` end to end through the async encryptor, returning
    /// the full blob and the file block. Chunks the plaintext at the
    /// segment size and marks the last chunk final.
    async fn encrypt_all<const S: u32>(
        url: &ruma::MxcUri,
        plaintext: &[u8],
    ) -> (Vec<u8>, FloeEncryptedFileKey) {
        let mut encryptor = FloeAsyncEncryptor::<_, S>::new(RustCryptoAeadBackend, url);
        let mut blob = encryptor.header().to_vec();

        let pt_per_seg = S as usize - SEG_OVERHEAD;
        let chunks: Vec<&[u8]> = if plaintext.is_empty() {
            vec![&[][..]]
        } else {
            plaintext.chunks(pt_per_seg).collect()
        };
        let last = chunks.len() - 1;
        for (i, chunk) in chunks.iter().enumerate() {
            let frame = encryptor.encrypt_segment(chunk, i == last).await.expect("encrypt segment");
            blob.extend_from_slice(&frame);
        }

        let file = encryptor.finish();
        (blob, FloeEncryptedFileKey { key: *file.key.k.as_inner(), size: file.size, v: file.v })
    }

    /// The bits of the file block the tests need, extracted before the
    /// (droppable, key-zeroizing) encryptor goes away.
    struct FloeEncryptedFileKey {
        key: [u8; KEY_SIZE],
        size: u64,
        v: String,
    }

    /// Decrypt a whole blob through the async decryptor at segment size `S`.
    async fn decrypt_all<const S: u32>(
        blob: &[u8],
        key: &[u8; KEY_SIZE],
        associated_data: &[u8],
        rotation_mask: Option<u64>,
    ) -> Result<Vec<u8>, FloeAsyncError> {
        let header = &blob[..HEADER_LEN];
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
        for chunk in blob[HEADER_LEN..].chunks(S as usize) {
            let plaintext = decryptor.decrypt_segment(chunk).await?;
            out.extend_from_slice(&plaintext);
        }
        Ok(out)
    }

    /// Decrypt a blob with the canonical `floe-rs` decryptor — the byte-compat
    /// oracle. Success proves our framing and every derived key are identical
    /// to the reference construction.
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

    /// The framing constants must equal `floe-rs`'s own, or the blobs diverge.
    #[test]
    fn framing_constants_match_floe_rs() {
        assert_eq!(HEADER_LEN, Header::LENGTH, "header length");
        assert_eq!(SEG_OVERHEAD, Segment::<ENC_SEG_LEN>::overhead(), "segment overhead");
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
            block_on(decrypt_all::<S>(&ciphertext, &key, KAT_AAD, rotation_mask)).expect("decrypt");
        assert_eq!(plaintext, decrypted, "decrypted KAT mismatch");
    }

    // The full canonical FLOE KAT suite (22 vectors, all five reference impls),
    // decrypted through the async driver. Vectors are vendored alongside the
    // synchronous adapter in `floe_test_vectors/`.
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
        let pt_per_seg = ENC_SEG_LEN as usize - SEG_OVERHEAD;

        // A partial final segment, an exact segment multiple (full final), and empty.
        let sizes = [pt_per_seg * 2 + 50_000, pt_per_seg * 3, 0];
        for size in sizes {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

            let (blob, file) = block_on(encrypt_all::<ENC_SEG_LEN>(&url, &plaintext));
            assert_eq!(file.v, super::FLOE_V0);
            assert_eq!(file.size, plaintext.len() as u64);

            let self_decrypted =
                block_on(decrypt_all::<ENC_SEG_LEN>(&blob, &file.key, url.as_bytes(), None))
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
        let pt_per_seg = ENC_SEG_LEN as usize - SEG_OVERHEAD;
        let plaintext: Vec<u8> = (0..(pt_per_seg * 2 + 10)).map(|i| (i % 251) as u8).collect();

        let (blob, _) = block_on(encrypt_all::<ENC_SEG_LEN>(&url, &plaintext));
        assert_eq!(
            &blob[HEADER_LEN..HEADER_LEN + 4],
            &[0xFF, 0xFF, 0xFF, 0xFF],
            "the first segment must be framed as non-final"
        );
        assert!(blob.len() > HEADER_LEN + ENC_SEG_LEN as usize, "expected multiple segments");
    }

    /// The mxc `url` is bound in, so decrypting under a different `url` fails
    /// the header tag at construction.
    #[test]
    fn wrong_url_aad_fails_header_tag() {
        let url = mxc("mxc://verji.example/abc123");
        let (blob, file) = block_on(encrypt_all::<ENC_SEG_LEN>(&url, b"hello world"));

        let wrong = mxc("mxc://verji.example/DIFFERENT");
        let result = block_on(decrypt_all::<ENC_SEG_LEN>(&blob, &file.key, wrong.as_bytes(), None));
        assert!(
            matches!(result, Err(FloeAsyncError::HeaderTag)),
            "a wrong url-AAD must fail the header tag, got {result:?}"
        );
    }

    /// A tampered segment fails authentication at the AEAD backend.
    #[test]
    fn tampered_segment_fails_authentication() {
        let url = mxc("mxc://verji.example/tamper");
        let (mut blob, file) = block_on(encrypt_all::<ENC_SEG_LEN>(&url, b"authentic bytes"));

        // Flip a ciphertext byte in the (single, final) segment.
        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        let result = block_on(decrypt_all::<ENC_SEG_LEN>(&blob, &file.key, url.as_bytes(), None));
        assert!(
            matches!(result, Err(FloeAsyncError::Aead(_))),
            "a tampered segment must fail authentication, got {result:?}"
        );
    }
}

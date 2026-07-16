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

//! Async WASM (WebCrypto) surface for streaming FLOE file encryption.
//!
//! This is the web counterpart of the native uniffi FLOE binding
//! ([`super::floe`]): the same shape — `floeEncrypt`/`floeDecrypt` driven by a
//! host byte **source** and **sink**, returning/consuming a FLOE file block —
//! but asynchronous. On the web the per-segment AES-256-GCM runs on the
//! browser's `crypto.subtle` (hardware AES) via `matrix-sdk-crypto`'s
//! [`WebCryptoAeadBackend`], so the driver and its source/sink callbacks are
//! all Promise-based. It is a raw `#[wasm_bindgen]` surface rather than uniffi
//! because the uniffi bindings are generated from the *synchronous* native
//! metadata and cannot describe this async path; the surface (names, records,
//! source/sink roles) is kept identical to the native binding.
//!
//! Only one ≤256 KiB chunk crosses the boundary at a time, so a multi-gigabyte
//! file is never buffered whole.

use js_sys::{Error as JsError, Uint8Array};
use matrix_sdk::ruma::{
    OwnedMxcUri,
    serde::{Base64, base64::UrlSafe},
};
use matrix_sdk_base::crypto::{
    ENC_SEG_LEN, FLOE_HEADER_LEN, FLOE_V0, FLOE_V0_PLAINTEXT_SEG_LEN, FloeAsyncDecryptor,
    FloeAsyncEncryptor, FloeAsyncError, FloeEncryptedFile as CoreFloeEncryptedFile,
    FloeJwk as CoreFloeJwk, WebCryptoAeadBackend,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsCast, prelude::*};

/// TypeScript declarations for the host-implemented interfaces and the FLOE
/// records, so the generated surface matches the native binding's shape.
#[wasm_bindgen(typescript_custom_section)]
const FLOE_TYPESCRIPT: &'static str = r#"
/** A host-provided source of bytes to encrypt or decrypt. */
export interface FloeByteSource {
    /** Return up to `maxLen` bytes; an empty `Uint8Array` signals end of stream. */
    readChunk(maxLen: number): Promise<Uint8Array>;
}
/** A host-provided sink for the produced bytes, one <=256 KiB chunk at a time. */
export interface FloeByteSink {
    /** Consume the next chunk of produced bytes. */
    writeChunk(chunk: Uint8Array): Promise<void>;
}
/** The FLOE root key as a JWK `oct` block. */
export interface FloeJwk {
    kty: string;
    alg: string;
    /** The 32-byte root key, base64url-encoded. */
    k: string;
    ext: boolean;
    keyOps: string[];
}
/** The FLOE `file` block to embed in the room-encrypted event. */
export interface FloeEncryptedFile {
    url: string;
    v: string;
    key: FloeJwk;
    encSegLen: number;
    size: number;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "FloeByteSource")]
    pub type FloeByteSource;
    #[wasm_bindgen(method, catch, js_name = readChunk)]
    async fn read_chunk(this: &FloeByteSource, max_len: u32) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(typescript_type = "FloeByteSink")]
    pub type FloeByteSink;
    #[wasm_bindgen(method, catch, js_name = writeChunk)]
    async fn write_chunk(this: &FloeByteSink, chunk: Uint8Array) -> Result<(), JsValue>;

    #[wasm_bindgen(typescript_type = "FloeEncryptedFile")]
    pub type FloeEncryptedFileJs;
}

/// The JWK block, mirroring the native binding's record (camelCase for the JS
/// surface).
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WasmFloeJwk {
    kty: String,
    alg: String,
    k: String,
    ext: bool,
    key_ops: Vec<String>,
}

/// The FLOE `file` block, mirroring the native binding's record.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WasmFloeEncryptedFile {
    url: String,
    v: String,
    key: WasmFloeJwk,
    enc_seg_len: u32,
    size: u64,
}

impl From<CoreFloeEncryptedFile> for WasmFloeEncryptedFile {
    fn from(core: CoreFloeEncryptedFile) -> Self {
        // The core `FloeJwk` zeroizes on drop, so clone the small metadata and
        // encode the key rather than moving out of it.
        Self {
            url: core.url.to_string(),
            v: core.v.clone(),
            key: WasmFloeJwk {
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

impl WasmFloeEncryptedFile {
    /// Rebuild the `matrix-sdk-crypto` file block, decoding the base64url root
    /// key into its 32 bytes.
    fn into_core(self) -> Result<CoreFloeEncryptedFile, JsValue> {
        let key_bytes = Base64::<UrlSafe, Vec<u8>>::parse(&self.key.k)
            .map_err(|e| error(&format!("invalid root key: {e}")))?
            .into_inner();
        let key_bytes: [u8; 32] =
            key_bytes.try_into().map_err(|_| error("root key is not 32 bytes"))?;

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

fn error(message: &str) -> JsValue {
    JsError::new(message).into()
}

fn floe_error(error: FloeAsyncError) -> JsValue {
    JsError::new(&format!("FLOE: {error}")).into()
}

/// Read from `source` until `wanted` bytes are collected or the stream ends,
/// returning what was read (at most `wanted` bytes).
async fn fill(source: &FloeByteSource, wanted: usize) -> Result<Vec<u8>, JsValue> {
    let mut buffer: Vec<u8> = Vec::with_capacity(wanted);
    while buffer.len() < wanted {
        let remaining = (wanted - buffer.len()) as u32;
        let value = source.read_chunk(remaining).await?;
        let chunk: Uint8Array =
            value.dyn_into().map_err(|_| error("readChunk must resolve to a Uint8Array"))?;
        if chunk.length() == 0 {
            break;
        }
        let start = buffer.len();
        buffer.resize(start + chunk.length() as usize, 0);
        chunk.copy_to(&mut buffer[start..]);
    }
    Ok(buffer)
}

/// Hand one produced chunk to the sink.
async fn write_all(sink: &FloeByteSink, bytes: &[u8]) -> Result<(), JsValue> {
    sink.write_chunk(Uint8Array::from(bytes)).await
}

/// FLOE-encrypt the bytes the `source` yields, streaming the encrypted blob to
/// the `sink`, and return the FLOE `file` block for the room-encrypted event.
///
/// A fresh random root key is generated and `url` is bound as associated data,
/// so the blob only validates when served from that mxc location. The
/// per-segment AES-256-GCM runs on `crypto.subtle`.
#[wasm_bindgen(js_name = floeEncrypt)]
pub async fn floe_encrypt(
    source: FloeByteSource,
    sink: FloeByteSink,
    url: String,
) -> Result<FloeEncryptedFileJs, JsValue> {
    let mxc = OwnedMxcUri::from(url);
    let mut encryptor =
        FloeAsyncEncryptor::<WebCryptoAeadBackend, ENC_SEG_LEN>::new(WebCryptoAeadBackend, &mxc);

    let header = encryptor.header().to_vec();
    write_all(&sink, &header).await?;

    // One-segment look-ahead so the final segment's framing is known before it
    // is encrypted; every non-final segment carries exactly one full chunk.
    let chunk_size = FLOE_V0_PLAINTEXT_SEG_LEN;
    let mut current = fill(&source, chunk_size).await?;
    loop {
        let next =
            if current.len() == chunk_size { fill(&source, chunk_size).await? } else { Vec::new() };
        let is_final = next.is_empty();
        let frame = encryptor.encrypt_segment(&current, is_final).await.map_err(floe_error)?;
        write_all(&sink, &frame).await?;
        if is_final {
            break;
        }
        current = next;
    }

    let file = WasmFloeEncryptedFile::from(encryptor.finish());
    let value = serde_wasm_bindgen::to_value(&file).map_err(|e| error(&e.to_string()))?;
    Ok(value.unchecked_into())
}

/// FLOE-decrypt the blob the `source` yields for `file`, streaming the
/// recovered plaintext to the `sink`.
///
/// The header is validated against the file's key and `url` before any segment
/// is decrypted; a wrong key/`url` or a truncated stream is an error.
#[wasm_bindgen(js_name = floeDecrypt)]
pub async fn floe_decrypt(
    file: FloeEncryptedFileJs,
    source: FloeByteSource,
    sink: FloeByteSink,
) -> Result<(), JsValue> {
    let file: WasmFloeEncryptedFile =
        serde_wasm_bindgen::from_value(file.into()).map_err(|e| error(&e.to_string()))?;
    let core = file.into_core()?;
    if core.v != FLOE_V0 {
        return Err(error(&format!("unexpected FLOE version: {}", core.v)));
    }

    let key: [u8; 32] = *core.key.k.as_inner();
    let associated_data = core.url.as_bytes().to_vec();

    let header = fill(&source, FLOE_HEADER_LEN).await?;
    let mut decryptor = FloeAsyncDecryptor::<WebCryptoAeadBackend, ENC_SEG_LEN>::new(
        WebCryptoAeadBackend,
        &header,
        &key,
        &associated_data,
    )
    .map_err(floe_error)?;

    loop {
        let frame = fill(&source, ENC_SEG_LEN as usize).await?;
        if frame.is_empty() {
            break;
        }
        let plaintext = decryptor.decrypt_segment(&frame).await.map_err(floe_error)?;
        write_all(&sink, &plaintext).await?;
        if decryptor.is_done() {
            break;
        }
    }
    Ok(())
}

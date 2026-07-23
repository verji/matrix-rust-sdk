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

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use js_sys::{Error as JsError, Reflect, Uint8Array};
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
use wasm_bindgen_futures::JsFuture;

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

// --- Media transport ---------------------------------------------------------
//
// The web counterpart of the native `Client::floe_download`/`floe_upload`
// (`super::floe`): the transport does the HTTP itself, so the host supplies
// only the plaintext sink/source, and the whole file never crosses the
// boundary. On the web the ciphertext body is streamed through the browser's
// `fetch` + `ReadableStream` (reqwest's wasm backend cannot stream a response
// body), one ~256 KiB segment held at a time. The homeserver/front-door and
// auth are passed explicitly rather than pulled from a client handle — this raw
// `#[wasm_bindgen]` surface has none, unlike the native binding's FFI `Client`.

/// Call the global `fetch` from either a `Window` or a `WorkerGlobalScope` —
/// the SDK runs in a Web Worker on the web, where `window()` is absent.
async fn fetch_request(request: &web_sys::Request) -> Result<JsValue, JsValue> {
    let global = js_sys::global();
    if let Ok(window) = global.clone().dyn_into::<web_sys::Window>() {
        JsFuture::from(window.fetch_with_request(request)).await
    } else if let Ok(scope) = global.dyn_into::<web_sys::WorkerGlobalScope>() {
        JsFuture::from(scope.fetch_with_request(request)).await
    } else {
        Err(error("no fetch available: global scope is neither Window nor WorkerGlobalScope"))
    }
}

/// Reads a `fetch` response body (`ReadableStream`) and hands out an exact
/// number of bytes per call, buffering the remainder of each network chunk.
/// Returns fewer than `wanted` bytes only at the true end of the stream. This
/// lets the FLOE decryptor consume the ciphertext in header- and segment-sized
/// reads even though the network chunks don't align to those boundaries.
struct CiphertextStream {
    reader: web_sys::ReadableStreamDefaultReader,
    buffer: Vec<u8>,
    pos: usize,
    done: bool,
}

impl CiphertextStream {
    fn new(reader: web_sys::ReadableStreamDefaultReader) -> Self {
        Self { reader, buffer: Vec::new(), pos: 0, done: false }
    }

    async fn read_exact(&mut self, wanted: usize) -> Result<Vec<u8>, JsValue> {
        let mut out: Vec<u8> = Vec::with_capacity(wanted);
        while out.len() < wanted {
            if self.pos >= self.buffer.len() {
                if self.done {
                    break;
                }
                let result = JsFuture::from(self.reader.read()).await?;
                let is_done =
                    Reflect::get(&result, &JsValue::from_str("done"))?.as_bool().unwrap_or(false);
                if is_done {
                    self.done = true;
                    break;
                }
                let value = Reflect::get(&result, &JsValue::from_str("value"))?;
                let chunk: Uint8Array = value
                    .dyn_into()
                    .map_err(|_| error("response stream chunk is not a Uint8Array"))?;
                let n = chunk.length() as usize;
                self.buffer.resize(n, 0);
                chunk.copy_to(&mut self.buffer[..]);
                self.pos = 0;
                if n == 0 {
                    continue;
                }
            }
            let take = (self.buffer.len() - self.pos).min(wanted - out.len());
            out.extend_from_slice(&self.buffer[self.pos..self.pos + take]);
            self.pos += take;
        }
        Ok(out)
    }
}

/// Download the FLOE blob described by `file` from `homeserver` and stream the
/// recovered plaintext to `sink`.
///
/// The mxc in `file.url` is resolved to the homeserver media-download endpoint;
/// `fetch` follows the MSC3860 redirect to the object store and the ciphertext
/// body is streamed through the async FLOE decryptor into `sink`, one 256 KiB
/// segment at a time — the whole file is never buffered. `auth_token`, when
/// given, is sent as a bearer token on the homeserver request. The header is
/// validated against the file's key and `url` before any segment is decrypted;
/// a wrong key/`url` or a truncated stream is an error.
#[wasm_bindgen(js_name = floeDownload)]
pub async fn floe_download(
    file: FloeEncryptedFileJs,
    homeserver: String,
    auth_token: Option<String>,
    sink: FloeByteSink,
) -> Result<(), JsValue> {
    let file: WasmFloeEncryptedFile =
        serde_wasm_bindgen::from_value(file.into()).map_err(|e| error(&e.to_string()))?;
    let core = file.into_core()?;
    if core.v != FLOE_V0 {
        return Err(error(&format!("unexpected FLOE version: {}", core.v)));
    }

    // Build the homeserver media-download URL from the mxc (matches the native
    // transport's path); `fetch` follows the MSC3860 redirect to the store.
    let (server, media_id) = core.url.parts().map_err(|e| error(&format!("malformed mxc: {e}")))?;
    let download_url = format!(
        "{}/_matrix/media/v3/download/{}/{}",
        homeserver.trim_end_matches('/'),
        server,
        media_id
    );

    let headers = web_sys::Headers::new()?;
    if let Some(token) = &auth_token {
        headers.set("Authorization", &format!("Bearer {token}"))?;
    }
    let init = web_sys::RequestInit::new();
    init.set_headers(&headers);
    let request = web_sys::Request::new_with_str_and_init(&download_url, &init)?;

    let response: web_sys::Response = fetch_request(&request).await?.dyn_into()?;
    if !response.ok() {
        return Err(error(&format!("media download failed: HTTP {}", response.status())));
    }
    let body =
        response.body().ok_or_else(|| error("media download response has no body stream"))?;
    let reader: web_sys::ReadableStreamDefaultReader = body.get_reader().dyn_into()?;
    let mut stream = CiphertextStream::new(reader);

    let key: [u8; 32] = *core.key.k.as_inner();
    let associated_data = core.url.as_bytes().to_vec();

    let header = stream.read_exact(FLOE_HEADER_LEN).await?;
    let mut decryptor = FloeAsyncDecryptor::<WebCryptoAeadBackend, ENC_SEG_LEN>::new(
        WebCryptoAeadBackend,
        &header,
        &key,
        &associated_data,
    )
    .map_err(floe_error)?;

    loop {
        let frame = stream.read_exact(ENC_SEG_LEN as usize).await?;
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

/// Bytes accumulated per tus `PATCH`. Independent of the FLOE segment and the
/// server's S3 part size; larger means fewer round-trips but a bigger in-flight
/// buffer. Kept modest on the web to bound the working set.
const WASM_TUS_PATCH_CHUNK: usize = 8 * 1024 * 1024;

/// Padded standard base64 for tus `Upload-Metadata` values (as the native path;
/// tusd expects RFC 4648 with padding, unlike ruma's unpadded `Base64`).
fn base64_standard(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

/// Reserve an mxc via MSC2246 (`POST .../_matrix/media/v1/create`), returning
/// the `content_uri`.
async fn reserve_mxc(create_url: &str, auth_token: Option<&str>) -> Result<OwnedMxcUri, JsValue> {
    let headers = web_sys::Headers::new()?;
    if let Some(token) = auth_token {
        headers.set("Authorization", &format!("Bearer {token}"))?;
    }
    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    init.set_headers(&headers);
    let request = web_sys::Request::new_with_str_and_init(create_url, &init)?;

    let response: web_sys::Response = fetch_request(&request).await?.dyn_into()?;
    if !response.ok() {
        return Err(error(&format!("mxc reserve failed: HTTP {}", response.status())));
    }
    let json = JsFuture::from(response.json()?).await?;
    let content_uri = Reflect::get(&json, &JsValue::from_str("content_uri"))?
        .as_string()
        .ok_or_else(|| error("mxc create response has no content_uri"))?;
    Ok(OwnedMxcUri::from(content_uri))
}

/// tus 1.0 `creation` with deferred length, tagging the upload with its mxc.
/// Returns the created upload resource URL (resolved against `front_door`).
async fn tus_create(
    front_door: &str,
    media_id: &str,
    auth_token: Option<&str>,
) -> Result<String, JsValue> {
    let headers = web_sys::Headers::new()?;
    headers.set("Tus-Resumable", "1.0.0")?;
    headers.set("Upload-Defer-Length", "1")?;
    headers.set("Upload-Metadata", &format!("mxc {}", base64_standard(media_id.as_bytes())))?;
    if let Some(token) = auth_token {
        headers.set("Authorization", &format!("Bearer {token}"))?;
    }
    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    init.set_headers(&headers);
    let request = web_sys::Request::new_with_str_and_init(front_door, &init)?;

    let response: web_sys::Response = fetch_request(&request).await?.dyn_into()?;
    if !response.ok() {
        return Err(error(&format!("tus create failed: HTTP {}", response.status())));
    }
    let location = response
        .headers()
        .get("Location")?
        .ok_or_else(|| error("tus create returned no Location"))?;
    // The Location may be relative; resolve it against the front door.
    web_sys::Url::new_with_base(&location, front_door)
        .map(|u| u.href())
        .map_err(|_| error("tus create returned a malformed Location"))
}

/// tus `PATCH` one chunk at `offset`; on the final chunk, declare the total
/// length (resolving the deferred length). Returns the new offset.
async fn tus_patch(
    location: &str,
    offset: u64,
    chunk: &[u8],
    is_final: bool,
    auth_token: Option<&str>,
) -> Result<u64, JsValue> {
    let new_offset = offset + chunk.len() as u64;
    let headers = web_sys::Headers::new()?;
    headers.set("Tus-Resumable", "1.0.0")?;
    headers.set("Upload-Offset", &offset.to_string())?;
    headers.set("Content-Type", "application/offset+octet-stream")?;
    if is_final {
        headers.set("Upload-Length", &new_offset.to_string())?;
    }
    if let Some(token) = auth_token {
        headers.set("Authorization", &format!("Bearer {token}"))?;
    }
    let init = web_sys::RequestInit::new();
    init.set_method("PATCH");
    init.set_headers(&headers);
    let body = Uint8Array::from(chunk);
    init.set_body(body.as_ref());
    let request = web_sys::Request::new_with_str_and_init(location, &init)?;

    let response: web_sys::Response = fetch_request(&request).await?.dyn_into()?;
    if !response.ok() {
        return Err(error(&format!("tus PATCH failed: HTTP {}", response.status())));
    }
    Ok(new_offset)
}

/// Reserve an mxc, FLOE-encrypt the bytes from `source`, and stream the
/// ciphertext to the resumable-upload `front_door` (tus 1.0 → S3), returning
/// the FLOE `file` block to embed in the room-encrypted event.
///
/// A fresh random root key is generated and the reserved mxc is bound as
/// associated data, so the blob only validates when served from that location.
/// The plaintext is consumed as a stream and the ciphertext is sent in
/// `WASM_TUS_PATCH_CHUNK`-sized PATCHes — the whole file is never buffered.
/// `homeserver` is where the mxc is reserved; `auth_token`, when given, is sent
/// as a bearer token to both the homeserver and the front door.
#[wasm_bindgen(js_name = floeUpload)]
pub async fn floe_upload(
    source: FloeByteSource,
    front_door: String,
    homeserver: String,
    auth_token: Option<String>,
) -> Result<FloeEncryptedFileJs, JsValue> {
    let auth = auth_token.as_deref();

    // Reserve the mxc (MSC2246); its media id tags the tus upload so the front
    // door registers the stored object under this mxc.
    let create_url = format!("{}/_matrix/media/v1/create", homeserver.trim_end_matches('/'));
    let mxc = reserve_mxc(&create_url, auth).await?;
    let (_, media_id) = mxc.parts().map_err(|e| error(&format!("malformed reserved mxc: {e}")))?;
    let media_id = media_id.to_owned();

    let mut encryptor =
        FloeAsyncEncryptor::<WebCryptoAeadBackend, ENC_SEG_LEN>::new(WebCryptoAeadBackend, &mxc);
    let location = tus_create(&front_door, &media_id, auth).await?;

    // Accumulate ciphertext and flush full PATCH chunks; the final flush declares
    // the total length. Header first, then segments with a one-segment look-ahead
    // so the final segment's framing is known before it is encrypted.
    let mut offset: u64 = 0;
    let mut buffer: Vec<u8> = Vec::with_capacity(WASM_TUS_PATCH_CHUNK + ENC_SEG_LEN as usize);
    buffer.extend_from_slice(encryptor.header());

    let chunk_size = FLOE_V0_PLAINTEXT_SEG_LEN;
    let mut current = fill(&source, chunk_size).await?;
    loop {
        let next =
            if current.len() == chunk_size { fill(&source, chunk_size).await? } else { Vec::new() };
        let is_final = next.is_empty();
        let frame = encryptor.encrypt_segment(&current, is_final).await.map_err(floe_error)?;
        buffer.extend_from_slice(&frame);
        // Flush only while strictly more than a chunk remains, so a flushed chunk
        // is never the last one — the final PATCH (below) declares the length.
        while buffer.len() > WASM_TUS_PATCH_CHUNK {
            let chunk: Vec<u8> = buffer.drain(..WASM_TUS_PATCH_CHUNK).collect();
            offset = tus_patch(&location, offset, &chunk, false, auth).await?;
        }
        if is_final {
            break;
        }
        current = next;
    }
    // The remainder is non-empty (the header alone is 74 bytes) and declares the
    // final length.
    tus_patch(&location, offset, &buffer, true, auth).await?;

    let file = WasmFloeEncryptedFile::from(encryptor.finish());
    let value = serde_wasm_bindgen::to_value(&file).map_err(|e| error(&e.to_string()))?;
    Ok(value.unchecked_into())
}

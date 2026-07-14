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

//! Streaming FLOE media — additive beside the whole-buffer `upload()` /
//! `get_media_content()`.
//!
//! Upload reserves an mxc (MSC2246), FLOE-encrypts the plaintext, and streams
//! the ciphertext to a resumable-upload front door (tus 1.0 → S3 multipart,
//! WS-D). Download follows the MSC3860 redirect to the object store and streams
//! the ciphertext through the FLOE decryptor. The crypto core is sync
//! `std::io::Read`, so the framing runs on a blocking thread bridged to the
//! async HTTP layer.
//!
//! Three decoupled granularities apply: the FLOE 256 KiB segment, the tus PATCH
//! chunk below, and the server's S3 part size are all independent.

use std::io::{self, Read, Write};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use futures_util::TryStreamExt as _;
use matrix_sdk_base::crypto::{FloeEncryptedFile, FloeStreamEncryptor};
use ruma::MxcUri;
use tokio::sync::{mpsc, oneshot};
use tokio_util::io::{StreamReader, SyncIoBridge};
use url::Url;

use super::{Media, MediaError};
use crate::{Error, Result};

/// Bytes per tus `PATCH`. Kept modest so an interrupted upload resumes with
/// little re-send; independent of the FLOE segment and the S3 part size.
const TUS_PATCH_CHUNK: usize = 4 * 1024 * 1024;

impl Media {
    /// FLOE-encrypt the bytes `plaintext` yields and stream the ciphertext to
    /// the resumable-upload `front_door`, returning the
    /// [`FloeEncryptedFile`] block to put in the room-encrypted event.
    ///
    /// A fresh random FLOE root key is generated and the reserved mxc is bound
    /// as associated data, so the blob only validates when served from that
    /// location. The plaintext is consumed as a stream — the whole file is
    /// never buffered.
    pub async fn upload_floe(
        &self,
        plaintext: impl Read + Send + 'static,
        front_door: &Url,
    ) -> Result<FloeEncryptedFile> {
        // Reserve the mxc (MSC2246). Its media id tags the tus upload so the front
        // door can register the stored object under this mxc.
        let mxc = self.create_content_uri().await?.uri;
        let media_id =
            mxc.parts().map_err(|e| floe_err(format!("malformed reserved mxc: {e}")))?.1.to_owned();

        // Drive the sync FLOE encryptor on a blocking thread, piping ciphertext
        // chunks out through a channel and the finished file block back.
        let (chunk_tx, mut chunk_rx) = mpsc::channel::<io::Result<Bytes>>(2);
        let (file_tx, file_rx) = oneshot::channel::<FloeEncryptedFile>();
        let blocking = tokio::task::spawn_blocking(move || {
            let mut enc: FloeStreamEncryptor<'_, _> = FloeStreamEncryptor::new(plaintext, &mxc);
            let mut buf = vec![0u8; TUS_PATCH_CHUNK];
            loop {
                match read_fill(&mut enc, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if chunk_tx.blocking_send(Ok(Bytes::copy_from_slice(&buf[..n]))).is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = chunk_tx.blocking_send(Err(e));
                        return;
                    }
                }
            }
            let _ = file_tx.send(enc.finish());
        });

        // tus: create a deferred-length upload, then PATCH chunks. The final chunk
        // (known via one-ahead lookahead) declares the total length.
        let http = self.client.http_client();
        let location = tus_create(http, front_door, &media_id).await?;
        let mut offset: u64 = 0;
        let mut pending = chunk_rx.recv().await.transpose().map_err(floe_io)?;
        while let Some(chunk) = pending.take() {
            let next = chunk_rx.recv().await.transpose().map_err(floe_io)?;
            offset = tus_patch(http, &location, offset, &chunk, next.is_none()).await?;
            pending = next;
        }

        blocking.await.map_err(|e| floe_err(format!("encrypt task panicked: {e}")))?;
        file_rx.await.map_err(|_| floe_err("encryptor produced no file block".to_owned()))
    }

    /// Download and FLOE-decrypt the blob described by `file`, returning the
    /// plaintext.
    ///
    /// Buffers the whole plaintext in memory; for multi-gigabyte files prefer
    /// [`Media::get_floe_media_content_to`], which streams into a sink.
    pub async fn get_floe_media_content(&self, file: &FloeEncryptedFile) -> Result<Vec<u8>> {
        let reader = self.floe_ciphertext_reader(&file.url).await?;
        let file = file.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, MediaError> {
            let mut decryptor =
                file.decryptor(reader).map_err(|e| MediaError::FloeStreaming(e.to_string()))?;
            let mut plaintext = Vec::new();
            decryptor
                .read_to_end(&mut plaintext)
                .map_err(|e| MediaError::FloeStreaming(e.to_string()))?;
            Ok(plaintext)
        })
        .await
        .map_err(|e| floe_err(format!("decrypt task panicked: {e}")))?
        .map_err(Into::into)
    }

    /// Download and FLOE-decrypt the blob described by `file`, streaming the
    /// plaintext into `writer`; returns the number of plaintext bytes written.
    ///
    /// **Memory-bounded** — only one 256 KiB segment is held at a time, so this
    /// scales to multi-gigabyte files without ever buffering the whole
    /// plaintext (unlike [`Media::get_floe_media_content`]). The in-blob
    /// header tag is checked against the key and mxc, so a wrong location
    /// or key is rejected before any plaintext is written.
    pub async fn get_floe_media_content_to<W>(
        &self,
        file: &FloeEncryptedFile,
        mut writer: W,
    ) -> Result<u64>
    where
        W: Write + Send + 'static,
    {
        let reader = self.floe_ciphertext_reader(&file.url).await?;
        let file = file.clone();
        tokio::task::spawn_blocking(move || -> Result<u64, MediaError> {
            let mut decryptor =
                file.decryptor(reader).map_err(|e| MediaError::FloeStreaming(e.to_string()))?;
            io::copy(&mut decryptor, &mut writer)
                .map_err(|e| MediaError::FloeStreaming(e.to_string()))
        })
        .await
        .map_err(|e| floe_err(format!("decrypt task panicked: {e}")))?
        .map_err(Into::into)
    }

    /// Fetch the ciphertext for an mxc as a blocking `Read`, following the
    /// MSC3860 redirect to the object store. The bytes stream lazily — nothing
    /// is buffered here; the caller drives the (sync) FLOE decryptor over
    /// it on a blocking thread.
    async fn floe_ciphertext_reader(&self, mxc: &MxcUri) -> Result<Box<dyn Read + Send>> {
        let http = self.client.http_client();
        let download_url = self.floe_download_url(mxc)?;

        // Follow the MSC3860 redirect explicitly — the SDK's HTTP client may be
        // configured not to auto-follow cross-origin redirects.
        let mut resp = http.get(download_url).send().await?;
        if resp.status().is_redirection() {
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| floe_err("redirect without a Location header".to_owned()))?
                .to_owned();
            resp = http.get(&location).send().await?;
        }
        let resp = resp.error_for_status()?;

        let byte_stream = resp.bytes_stream().map_err(io::Error::other);
        Ok(Box::new(SyncIoBridge::new(StreamReader::new(byte_stream))))
    }

    /// The media-download URL for an mxc, against this client's homeserver.
    fn floe_download_url(&self, mxc: &MxcUri) -> Result<Url> {
        let (server, media_id) =
            mxc.parts().map_err(|e| floe_err(format!("malformed mxc: {e}")))?;
        self.client
            .homeserver()
            .join(&format!("/_matrix/media/v3/download/{server}/{media_id}"))
            .map_err(|e| floe_err(format!("could not build download url: {e}")))
    }
}

/// Read until `buf` is full or EOF; returns the number of bytes read (0 at
/// EOF).
fn read_fill(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// tus 1.0 `creation` with deferred length, tagging the upload with its mxc.
/// Returns the created upload resource URL.
async fn tus_create(http: &reqwest::Client, front_door: &Url, media_id: &str) -> Result<Url> {
    let resp = http
        .post(front_door.clone())
        .header("Tus-Resumable", "1.0.0")
        .header("Upload-Defer-Length", "1")
        .header("Upload-Metadata", format!("mxc {}", BASE64.encode(media_id)))
        .send()
        .await?
        .error_for_status()?;
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| floe_err("tus create returned no Location".to_owned()))?;
    front_door.join(location).map_err(|e| floe_err(format!("bad tus Location: {e}")))
}

/// tus `PATCH` one chunk at `offset`; on the final chunk, declare the total
/// length (resolving the deferred length). Returns the new offset.
async fn tus_patch(
    http: &reqwest::Client,
    location: &Url,
    offset: u64,
    chunk: &Bytes,
    is_last: bool,
) -> Result<u64> {
    let new_offset = offset + chunk.len() as u64;
    let mut req = http
        .patch(location.clone())
        .header("Tus-Resumable", "1.0.0")
        .header("Upload-Offset", offset.to_string())
        .header(reqwest::header::CONTENT_TYPE, "application/offset+octet-stream");
    if is_last {
        req = req.header("Upload-Length", new_offset.to_string());
    }
    req.body(chunk.clone()).send().await?.error_for_status()?;
    Ok(new_offset)
}

fn floe_err(msg: String) -> Error {
    Error::Media(MediaError::FloeStreaming(msg))
}

fn floe_io(e: io::Error) -> Error {
    Error::Media(MediaError::FloeStreaming(e.to_string()))
}

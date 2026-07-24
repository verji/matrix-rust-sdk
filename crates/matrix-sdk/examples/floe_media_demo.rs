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

//! FLOE huge-file media round-trip demonstrator (Phase 1).
//!
//! A minimal, headless Rust client on the FLOE-enabled fork. It reads a local
//! file, FLOE-encrypts and stream-uploads it through a resumable-upload front
//! door (tus 1.0 -> S3 multipart), then downloads and FLOE-decrypts it back,
//! and proves the plaintext round-trips byte-for-byte. This demonstrates the
//! MSC4016 envelope plus Matrix media up/down (MSC2246 reserve, MSC3860
//! redirect) end to end, streaming — the whole file is never buffered.
//!
//! There is no room here: the returned `FloeEncryptedFile` block is exactly
//! what a sender would put in the room-encrypted file event. Wiring it to and
//! from an actual room (login + Synapse + the file-message event) is Phase 2.
//!
//! ## Prerequisites
//!
//! The local Pass-2 media harness (MinIO + tusd + a mock MSC2246/MSC3860 media
//! server), from verji-src:
//! `doc/wip/huge-files-e2ee/spikes/pass2-media-harness/` (`docker compose up
//! -d`). No homeserver, no Tuwunel, no staging — all local docker.
//!
//! ## Run
//!
//! On Windows, `--no-default-features` avoids the system-sqlite3 link error;
//! the `testing` feature provides the no-login `MockClientBuilder` shortcut
//! (Phase 1 reserves an mxc via the authenticated media endpoint without a real
//! login — the mock ignores the dummy token).
//!
//! ```text
//! cargo run -p matrix-sdk --no-default-features \
//!     --features e2e-encryption,testing --example floe_media_demo -- [FILE]
//! ```
//!
//! `FILE` is optional; without it a ~5 MiB deterministic sample is generated
//! (deliberately not a multiple of the 256 KiB FLOE segment or the tus chunk,
//! so the multi-segment / final-partial / multi-chunk paths all run). Endpoints
//! are overridable via `MOCK_HOMESERVER` (default `http://localhost:8090`) and
//! `TUS_FRONT_DOOR` (default `http://localhost:8080/files/`).

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::Context as _;
use matrix_sdk::test_utils::client::MockClientBuilder;
use sha2::{Digest, Sha256};
use url::Url;

const DEFAULT_MOCK_HOMESERVER: &str = "http://localhost:8090";
const DEFAULT_TUS_FRONT_DOOR: &str = "http://localhost:8080/files/";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mock =
        std::env::var("MOCK_HOMESERVER").unwrap_or_else(|_| DEFAULT_MOCK_HOMESERVER.to_owned());
    let front_door_raw =
        std::env::var("TUS_FRONT_DOOR").unwrap_or_else(|_| DEFAULT_TUS_FRONT_DOOR.to_owned());
    let front_door = Url::parse(&front_door_raw).context("invalid TUS_FRONT_DOOR")?;

    // Resolve the source: a given file, or a generated deterministic sample.
    let src_path = match std::env::args().nth(1) {
        Some(p) => PathBuf::from(p),
        None => {
            let p = std::env::temp_dir().join("floe_demo_sample.bin");
            let len = 5 * 1024 * 1024 + 12_345;
            write_sample(&p, len).context("generating the sample file")?;
            println!("no FILE argument -> generated a {len}-byte sample at {}", p.display());
            p
        }
    };

    let (src_sha, src_len) = sha256_and_len(&src_path).context("hashing the source file")?;
    println!("source     : {} ({src_len} bytes, sha256 {src_sha})", src_path.display());
    println!("homeserver : {mock}");
    println!("front door : {front_door}");
    println!();

    // No-login client pointed at the mock (Phase 1 shortcut; Phase 2 does a real
    // login).
    let client = MockClientBuilder::new(Some(&mock)).build().await;
    let media = client.media();

    // Upload: reserve an mxc (MSC2246) -> FLOE-encrypt -> stream ciphertext to
    // the tus front door -> S3. The plaintext is consumed as a stream.
    let src = std::fs::File::open(&src_path).context("opening the source file")?;
    let t = Instant::now();
    let file_block = media
        .upload_floe(src, &front_door)
        .await
        .context("upload_floe failed (is the Pass-2 harness up? docker compose up -d)")?;
    let up_elapsed = t.elapsed();
    let ruma::events::room::EncryptedFileInfo::Floe(info) = &file_block.info else {
        anyhow::bail!("upload_floe did not return a FLOE block");
    };
    println!(
        "uploaded   : mxc={} v={} enc_seg_len={} size={} in {up_elapsed:?}",
        file_block.url,
        file_block.info.version(),
        info.enc_seg_len,
        info.size,
    );
    println!(
        "             (this ruma EncryptedFile block is what goes in the room event — Phase 2)"
    );

    // Download: follow the MSC3860 redirect and stream the plaintext straight to
    // disk (bounded memory). tusd acks the upload before its post-finish hook
    // registers the mxc with the mock, so poll through that window — in a real
    // flow the room-event round-trip hides it.
    let out_path = std::env::temp_dir().join("floe_demo_download.bin");
    let t = Instant::now();
    let mut written = None;
    for attempt in 0..40 {
        let out = std::fs::File::create(&out_path).context("creating the download file")?;
        match media.get_floe_media_content_to(&file_block, out).await {
            Ok(n) => {
                written = Some(n);
                break;
            }
            Err(e) if attempt < 39 => {
                if attempt == 0 {
                    println!("download   : waiting for the tus hook to register the mxc...");
                }
                let _ = e;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => return Err(e).context("get_floe_media_content_to failed after retries"),
        }
    }
    let written = written.context("download never became ready")?;
    let down_elapsed = t.elapsed();
    println!("downloaded : {written} bytes -> {} in {down_elapsed:?}", out_path.display());
    println!();

    // Verify byte-exact.
    let (out_sha, out_len) = sha256_and_len(&out_path).context("hashing the downloaded file")?;
    println!("verify     : {out_len} bytes, sha256 {out_sha}");

    if out_len == src_len && written == src_len && out_sha == src_sha {
        println!("\nROUND-TRIP OK — {src_len} bytes byte-exact (SHA-256 identical).");
        Ok(())
    } else {
        eprintln!(
            "\nROUND-TRIP MISMATCH — src_len={src_len} out_len={out_len} written={written}\n\
             src_sha={src_sha}\nout_sha={out_sha}"
        );
        std::process::exit(1);
    }
}

/// Stream a file through SHA-256, returning the hex digest and byte length
/// without ever buffering the whole file.
fn sha256_and_len(path: &Path) -> anyhow::Result<(String, u64)> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    let hex = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>();
    Ok((hex, total))
}

/// Write `len` bytes of deterministic content (`i % 251`) to `path`, streamed
/// in 1 MiB chunks.
fn write_sample(path: &Path, len: usize) -> anyhow::Result<()> {
    let mut f = std::fs::File::create(path)?;
    let mut buf = vec![0u8; 1024 * 1024];
    let mut written = 0usize;
    while written < len {
        let chunk = buf.len().min(len - written);
        for (j, b) in buf[..chunk].iter_mut().enumerate() {
            *b = ((written + j) % 251) as u8;
        }
        f.write_all(&buf[..chunk])?;
        written += chunk;
    }
    f.flush()?;
    Ok(())
}

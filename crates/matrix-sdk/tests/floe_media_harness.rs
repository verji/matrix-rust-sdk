// Copyright 2026 Verji AS
//
// Licensed under the Apache License, Version 2.0.

//! Opt-in end-to-end test for the streaming FLOE media methods against the LIVE
//! Pass-2 media harness (docker compose in
//! `verji-src/doc/wip/huge-files-e2ee/spikes/pass2-media-harness/`).
//!
//! Bring the harness up first, then:
//!
//! ```text
//! cargo test -p matrix-sdk --features testing --test floe_media_harness \
//!     -- --ignored --nocapture
//! ```
//!
//! Exercises reserve mxc (MSC2246, via the mock `/create`) -> FLOE-encrypt ->
//! resumable tus upload -> MSC3860 redirect download -> FLOE-decrypt, and
//! asserts the plaintext round-trips byte-for-byte.

#![cfg(all(feature = "e2e-encryption", feature = "testing", not(target_family = "wasm")))]

use std::{
    io::{Cursor, Read, Write},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use matrix_sdk::test_utils::client::MockClientBuilder;
use url::Url;

const MOCK_HOMESERVER: &str = "http://localhost:8090";
const TUS_FRONT_DOOR: &str = "http://localhost:8080/files/";

#[tokio::test]
#[ignore = "requires the live Pass-2 media harness (docker compose up -d)"]
async fn floe_media_roundtrip() {
    let client = MockClientBuilder::new(Some(MOCK_HOMESERVER)).build().await;
    let media = client.media();

    // ~5 MiB, deliberately not a multiple of the 256 KiB segment or the 4 MiB
    // tus chunk, so multi-segment + final-partial + multi-chunk paths all run.
    let plaintext: Vec<u8> = (0..(5 * 1024 * 1024 + 12_345)).map(|i| (i % 251) as u8).collect();
    let front_door = Url::parse(TUS_FRONT_DOOR).unwrap();

    let file = media
        .upload_floe(Cursor::new(plaintext.clone()), &front_door)
        .await
        .expect("upload_floe failed");
    eprintln!(
        "uploaded: url={} v={} enc_seg_len={} size={}",
        file.url, file.v, file.enc_seg_len, file.size
    );
    assert_eq!(file.v, "org.verji.msc4016.floe.v0");
    assert_eq!(file.size, plaintext.len() as u64);

    // The tus front door acks the upload (PATCH 204) before its post-finish hook
    // registers the mxc with the media server, so poll through that window. In a
    // real flow the gap is hidden by the room-event round-trip between sender and
    // recipient.
    let mut got = None;
    for attempt in 0..20 {
        match media.get_floe_media_content(&file).await {
            Ok(bytes) => {
                got = Some(bytes);
                break;
            }
            Err(e) if attempt < 19 => {
                eprintln!("download not ready yet (attempt {attempt}): {e}");
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => panic!("get_floe_media_content failed after retries: {e}"),
        }
    }
    let got = got.expect("download never became ready");

    assert_eq!(got.len(), plaintext.len(), "downloaded length mismatch");
    assert!(got == plaintext, "round-trip byte mismatch");
    eprintln!("round-trip OK: {} bytes byte-exact", got.len());
}

/// Large-scale streaming round-trip — proves bounded-memory GB-scale transfer.
///
/// The plaintext is **generated on the fly** (never buffered) on the way in,
/// and **verified on the fly** (never buffered) on the way out, so the test
/// itself holds no more than its working set regardless of file size — the real
/// proof that `upload_floe` / `get_floe_media_content_to` stream rather than
/// buffer.
///
/// Size via `FLOE_TEST_SIZE_MB` (default 2048). E.g. the headline 4 GB claim:
/// `FLOE_TEST_SIZE_MB=4096 cargo test -p matrix-sdk --no-default-features \
///   --features e2e-encryption,testing --test floe_media_harness \
///   -- --ignored --nocapture floe_media_large_streaming`
#[tokio::test]
#[ignore = "requires the live harness; GB-scale (set FLOE_TEST_SIZE_MB)"]
async fn floe_media_large_streaming() {
    let size_mb: u64 =
        std::env::var("FLOE_TEST_SIZE_MB").ok().and_then(|s| s.parse().ok()).unwrap_or(2048);
    let total = size_mb * 1024 * 1024;
    eprintln!("large streaming test: {size_mb} MiB ({total} bytes)");

    let client = MockClientBuilder::new(Some(MOCK_HOMESERVER)).build().await;
    let media = client.media();
    let front_door = Url::parse(TUS_FRONT_DOOR).unwrap();

    let t = Instant::now();
    let file = media.upload_floe(FloeGen::new(total), &front_door).await.expect("upload_floe");
    eprintln!("uploaded {total} B in {:?} (v={}, size={})", t.elapsed(), file.v, file.size);
    assert_eq!(file.size, total, "declared size mismatch");

    // Stream the download straight into a verifier (no buffering), retrying
    // through the front-door registration window.
    let state = Arc::new(Mutex::new((0u64, true)));
    let t = Instant::now();
    let mut written = None;
    for attempt in 0..40 {
        *state.lock().unwrap() = (0, true);
        match media.get_floe_media_content_to(&file, VerifySink { state: state.clone() }).await {
            Ok(n) => {
                written = Some(n);
                break;
            }
            Err(e) if attempt < 39 => {
                eprintln!("download not ready (attempt {attempt}): {e}");
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => panic!("get_floe_media_content_to failed: {e}"),
        }
    }
    let written = written.expect("download never became ready");
    let (pos, ok) = *state.lock().unwrap();
    eprintln!("downloaded + verified {written} B in {:?}", t.elapsed());
    assert_eq!(written, total, "bytes written mismatch");
    assert_eq!(pos, total, "verified position mismatch");
    assert!(ok, "streaming byte-verify failed — corruption");
    eprintln!("large streaming OK: {total} B bounded-memory byte-exact");
}

/// Deterministic plaintext byte at position `i` (shared by generator +
/// verifier).
fn gen_byte(i: u64) -> u8 {
    (i.wrapping_mul(1_099_511_628_211) >> 17) as u8
}

/// A `Read` that yields `total` generated bytes without ever buffering them.
struct FloeGen {
    pos: u64,
    end: u64,
}

impl FloeGen {
    fn new(total: u64) -> Self {
        Self { pos: 0, end: total }
    }
}

impl Read for FloeGen {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = (buf.len() as u64).min(self.end - self.pos) as usize;
        for b in &mut buf[..n] {
            *b = gen_byte(self.pos);
            self.pos += 1;
        }
        Ok(n)
    }
}

/// A `Write` sink that verifies each byte against `gen_byte` as it streams,
/// tracking `(position, all-ok)` in shared state — never buffers.
struct VerifySink {
    state: Arc<Mutex<(u64, bool)>>,
}

impl Write for VerifySink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut g = self.state.lock().unwrap();
        let (mut pos, mut ok) = *g;
        for &b in buf {
            if b != gen_byte(pos) {
                ok = false;
            }
            pos += 1;
        }
        *g = (pos, ok);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

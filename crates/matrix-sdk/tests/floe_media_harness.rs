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

use std::io::Cursor;

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
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            Err(e) => panic!("get_floe_media_content failed after retries: {e}"),
        }
    }
    let got = got.expect("download never became ready");

    assert_eq!(got.len(), plaintext.len(), "downloaded length mismatch");
    assert!(got == plaintext, "round-trip byte mismatch");
    eprintln!("round-trip OK: {} bytes byte-exact", got.len());
}

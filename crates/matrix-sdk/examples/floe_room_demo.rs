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

//! FLOE huge-file demonstrator, Phase 2 — *to and from a Matrix room*.
//!
//! Builds on the Phase 1 media round-trip ([`floe_media_demo`]) by wiring the
//! encrypted file through a **real homeserver room with end-to-end
//! encryption**:
//!
//! 1. register + log in two users, `alice` (sender) and `bob` (receiver), each
//!    with its own in-memory crypto store;
//! 2. alice creates an **encrypted** room and invites bob; bob joins; both sync
//!    so the Megolm session and device keys are established;
//! 3. alice `upload_floe`s a local file to the media front door (tus → S3),
//!    getting a [`FloeEncryptedFile`] block;
//! 4. alice sends that block into the room inside a **Megolm-encrypted**
//!    message event — the FLOE root key travels *inside* the room encryption;
//! 5. bob syncs, decrypts the event, extracts the block,
//!    `get_floe_media_content_to`s it, and verifies the plaintext is
//!    **byte-exact**.
//!
//! The genuinely new part over Phase 1 is step 4/5: the file event flowing
//! through a real homeserver under E2EE, sender → room → receiver.
//!
//! Media stays **homeserver-independent**: rooms live on Synapse, but the media
//! bytes go through the beside-the-homeserver front door (the Pass-2 mock), so
//! Synapse never sees the ciphertext. A single mock-pointed client serves both
//! the upload and the download (the mock media store is unauthenticated shared
//! infra).
//!
//! ## Prerequisites (all local, no staging)
//!
//! - The Pass-2 media harness (MinIO + tusd + mock), from verji-src:
//!   `doc/wip/huge-files-e2ee/spikes/pass2-media-harness/` (`docker compose up
//!   -d`).
//! - A local Synapse, from this repo's integration-testing assets (port 8228,
//!   registration enabled): `testing/matrix-sdk-integration-testing/assets/`
//!   (`docker compose up -d --build`).
//!
//! ## Run
//!
//! ```text
//! cargo run -p matrix-sdk --no-default-features \
//!     --features e2e-encryption,testing --example floe_room_demo -- [FILE]
//! ```
//!
//! `FILE` is optional (a ~5 MiB sample is generated). Endpoints override via
//! `HOMESERVER_URL` (default `http://localhost:8228`), `MOCK_HOMESERVER`
//! (default `http://localhost:8090`) and `TUS_FRONT_DOOR`
//! (default `http://localhost:8080/files/`).

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context as _, Result};
use matrix_sdk::{
    Client,
    config::SyncSettings,
    encryption::EncryptionSettings,
    ruma::{
        api::client::{
            account::register::v3::Request as RegistrationRequest,
            room::create_room::v3::Request as CreateRoomRequest, uiaa,
        },
        events::room::message::{MessageType, RoomMessageEventContent, SyncRoomMessageEvent},
    },
    test_utils::client::MockClientBuilder,
};
use sha2::{Digest, Sha256};
use url::Url;

#[tokio::main]
async fn main() -> Result<()> {
    let hs = std::env::var("HOMESERVER_URL").unwrap_or_else(|_| "http://localhost:8228".to_owned());
    let mock =
        std::env::var("MOCK_HOMESERVER").unwrap_or_else(|_| "http://localhost:8090".to_owned());
    let front_door = Url::parse(
        &std::env::var("TUS_FRONT_DOOR")
            .unwrap_or_else(|_| "http://localhost:8080/files/".to_owned()),
    )
    .context("invalid TUS_FRONT_DOOR")?;

    // Resolve the source: a given file, or a generated deterministic sample.
    let src_path = match std::env::args().nth(1) {
        Some(p) => PathBuf::from(p),
        None => {
            let p = std::env::temp_dir().join("floe_room_sample.bin");
            let len = 5 * 1024 * 1024 + 12_345;
            write_sample(&p, len).context("generating the sample file")?;
            println!("no FILE argument -> generated a {len}-byte sample at {}", p.display());
            p
        }
    };
    let (src_sha, src_len) = sha256_and_len(&src_path).context("hashing the source file")?;
    println!("source     : {} ({src_len} bytes, sha256 {src_sha})", src_path.display());
    println!("homeserver : {hs}");
    println!("media front: {mock}  (tus {front_door})");
    println!();

    // Fresh users per run (timestamp suffix) so each run is a clean pair — no
    // stale devices from earlier runs.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let alice = register_and_login(&hs, &format!("floe_alice_{stamp}")).await?;
    let bob = register_and_login(&hs, &format!("floe_bob_{stamp}")).await?;
    println!("alice      : {}", alice.user_id().context("alice not logged in")?);
    println!("bob        : {}", bob.user_id().context("bob not logged in")?);

    let mut alice_sync = Syncer::new(alice.clone());
    let mut bob_sync = Syncer::new(bob.clone());

    // Prime both clients (upload device keys).
    alice_sync.once().await?;
    bob_sync.once().await?;

    // alice creates an encrypted room and invites bob.
    let mut request = CreateRoomRequest::new();
    request.invite = vec![bob.user_id().unwrap().to_owned()];
    request.is_direct = true;
    let alice_room = alice.create_room(request).await.context("alice create_room")?;
    alice_room.enable_encryption().await.context("enable_encryption")?;
    let room_id = alice_room.room_id().to_owned();
    println!("room       : {room_id} (encrypted)");
    alice_sync.once().await?;

    // bob sees the invite and joins.
    let bob_room = {
        let mut found = None;
        for _ in 0..20 {
            bob_sync.once().await?;
            if let Some(r) = bob.get_room(&room_id) {
                found = Some(r);
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        found.context("bob never saw the room invite")?
    };
    bob_room.join().await.context("bob join")?;
    // Settle memberships + device-key discovery on both sides before sending.
    alice_sync.once().await?;
    bob_sync.once().await?;
    alice_sync.once().await?;
    println!("bob joined the encrypted room");
    println!();

    // alice uploads the file to the (homeserver-independent) media front door.
    let media_client = MockClientBuilder::new(Some(&mock)).build().await;
    let media = media_client.media();
    let file_block = media
        .upload_floe(std::fs::File::open(&src_path)?, &front_door)
        .await
        .context("upload_floe (is the Pass-2 harness up?)")?;
    let ruma::events::room::EncryptedFileInfo::Floe(info) = &file_block.info else {
        anyhow::bail!("upload_floe did not return a FLOE block");
    };
    println!("uploaded   : mxc={} size={}", file_block.url, info.size);

    // alice sends the FloeEncryptedFile block into the room, Megolm-encrypted.
    let payload = serde_json::to_string(&file_block).context("serialize file block")?;
    alice_room
        .send(RoomMessageEventContent::text_plain(payload))
        .await
        .context("alice send encrypted file event")?;
    println!("sent       : encrypted file event -> room (the FLOE key rides inside E2EE)");

    // bob receives + decrypts the event and pulls the block back out.
    let received: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    {
        let slot = received.clone();
        bob.add_event_handler(move |ev: SyncRoomMessageEvent| {
            let slot = slot.clone();
            async move {
                if let Some(orig) = ev.as_original()
                    && let MessageType::Text(t) = &orig.content.msgtype
                {
                    *slot.lock().unwrap() = Some(t.body.clone());
                }
            }
        });
    }
    let body = {
        let mut got = None;
        for _ in 0..40 {
            bob_sync.once().await?;
            if let Some(b) = received.lock().unwrap().clone() {
                got = Some(b);
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        got.context("bob never received/decrypted the file event")?
    };
    let received_block: ruma::events::room::EncryptedFile =
        serde_json::from_str(&body).context("parse the EncryptedFile from the decrypted event")?;
    println!("received   : bob decrypted the event; mxc={}", received_block.url);

    // bob downloads + FLOE-decrypts, polling through the tus-hook window.
    let out_path = std::env::temp_dir().join("floe_room_download.bin");
    let mut written = None;
    for attempt in 0..40 {
        let out = std::fs::File::create(&out_path)?;
        match media.get_floe_media_content_to(&received_block, out).await {
            Ok(n) => {
                written = Some(n);
                break;
            }
            Err(e) if attempt < 39 => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => return Err(e).context("get_floe_media_content_to failed after retries"),
        }
    }
    let written = written.context("download never became ready")?;
    let (out_sha, out_len) = sha256_and_len(&out_path).context("hashing the downloaded file")?;
    println!("downloaded : {written} bytes -> {}", out_path.display());
    println!("verify     : {out_len} bytes, sha256 {out_sha}");

    if out_len == src_len && written == src_len && out_sha == src_sha {
        println!(
            "\nPHASE 2 OK — file went alice -> encrypted room -> bob, {src_len} bytes byte-exact \
             (SHA-256 identical)."
        );
        Ok(())
    } else {
        eprintln!(
            "\nPHASE 2 MISMATCH — src_len={src_len} out_len={out_len} written={written}\n\
             src_sha={src_sha}\nout_sha={out_sha}"
        );
        std::process::exit(1);
    }
}

/// Register a fresh user (dummy-auth UIAA) and log in, mirroring the SDK's
/// integration-test helper. Uses an in-memory store (no persistence needed for
/// a one-shot demo).
async fn register_and_login(homeserver: &str, username: &str) -> Result<Client> {
    let client = Client::builder()
        .homeserver_url(homeserver)
        .with_encryption_settings(EncryptionSettings::default())
        .build()
        .await
        .context("building the client")?;

    let auth = client.matrix_auth();
    let mut try_login = true;
    if let Err(resp) = auth.register(RegistrationRequest::new()).await
        && resp.as_uiaa_response().is_some()
    {
        let mut req = RegistrationRequest::new();
        req.username = Some(username.to_owned());
        req.password = Some(username.to_owned());
        req.auth = Some(uiaa::AuthData::Dummy(uiaa::Dummy::new()));
        try_login = auth.register(req).await.is_err();
    }
    if try_login {
        auth.login_username(username, username).await.context("login")?;
    }
    Ok(client)
}

/// A `sync_once` wrapper that threads the `next_batch` token, so syncs after
/// the first are incremental and reliably deliver new events to handlers.
struct Syncer {
    client: Client,
    token: Option<String>,
}

impl Syncer {
    fn new(client: Client) -> Self {
        Self { client, token: None }
    }

    async fn once(&mut self) -> Result<()> {
        let mut settings = SyncSettings::default().timeout(Duration::from_secs(2));
        if let Some(token) = &self.token {
            settings = settings.token(token.clone());
        }
        let response = self.client.sync_once(settings).await.context("sync_once")?;
        self.token = Some(response.next_batch);
        Ok(())
    }
}

/// Stream a file through SHA-256, returning the hex digest and byte length.
fn sha256_and_len(path: &Path) -> Result<(String, u64)> {
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

/// Write `len` bytes of deterministic content (`i % 251`) to `path`.
fn write_sample(path: &Path, len: usize) -> Result<()> {
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

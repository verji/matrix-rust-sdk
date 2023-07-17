// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use std::sync::Arc;

use ruma::{
    api::client::dehydrated_device::{put_dehydrated_device, DehydratedDeviceData},
    assign,
    events::AnyToDeviceEvent,
    serde::Raw,
    DeviceId, UserId,
};
use tokio::sync::Mutex;
use tracing::{instrument, trace};

use crate::{
    olm::{Account, PrivateCrossSigningIdentity},
    store::{IntoCryptoStore, MemoryStore, Store},
    verification::VerificationMachine,
    OlmError, OlmMachine, ReadOnlyAccount,
};

pub struct DehydratedDevices {
    pub(crate) inner: OlmMachine,
}

impl DehydratedDevices {
    pub fn create(&self) -> DehydratedDevice {
        DehydratedDevice::new(self.inner.user_id(), self.inner.store().private_identity())
    }

    pub async fn resume_rehydration(&self) -> Result<RehydratedDevice, serde_json::Error> {
        todo!()
    }

    pub async fn rehydrate(
        &self,
        pickle_key: &[u8; 32],
        device_id: &DeviceId,
        device_data: Raw<DehydratedDeviceData>,
    ) -> Result<RehydratedDevice, serde_json::Error> {
        let rehydrated = self.inner.rehydrate(pickle_key, device_id, device_data).await.unwrap();

        Ok(RehydratedDevice { rehydrated, original: self.inner.to_owned() })
    }
}

#[derive(Debug)]
pub struct RehydratedDevice {
    rehydrated: OlmMachine,
    original: OlmMachine,
}

impl RehydratedDevice {
    #[instrument(
        skip_all,
        fields(
            user_id = %self.original.user_id(),
            rehydrated_device_id = %self.rehydrated.device_id(),
            original_device_id = %self.original.device_id()
        )
    )]
    pub async fn receive_events(
        &self,
        events: Vec<Raw<AnyToDeviceEvent>>,
    ) -> Result<usize, OlmError> {
        trace!("Receiving events for a rehydrated Device");

        let (_, changes) = self
            .rehydrated
            .receive_sync_changes_helper(events, &Default::default(), &Default::default(), None)
            .await?;

        let room_keys = &changes.inbound_group_sessions;
        let room_key_count = room_keys.len();

        trace!(room_key_count = room_keys.len(), "Collected room keys from the rehydrated device");

        self.original.store().save_inbound_group_sessions(&room_keys).await?;
        self.rehydrated.store().save_changes(changes).await?;

        Ok(room_key_count)
    }
}

pub struct DehydratedDevice {
    account: Account,
}

impl DehydratedDevice {
    pub fn new(user_id: &UserId, user_identity: Arc<Mutex<PrivateCrossSigningIdentity>>) -> Self {
        let account = ReadOnlyAccount::new(user_id);
        let store = MemoryStore::new().into_crypto_store();

        let verification_machine =
            VerificationMachine::new(account.clone(), user_identity.clone(), store.clone());
        let store = Store::new(user_id.into(), user_identity, store, verification_machine);

        let account = Account { inner: account, store };

        Self { account }
    }

    #[instrument(
        skip_all, fields(
            user_id = %self.account.user_id(),
            device_id = %self.account.device_id(),
            identity_keys = ?self.account.identity_keys,
        )
    )]
    pub async fn keys_for_upload(
        &self,
        initial_device_display_name: String,
        pickle_key: &[u8; 32],
    ) -> put_dehydrated_device::unstable::Request {
        // TODO: We need to ensure that a fallback key has been generated.
        let (device_keys, one_time_keys, fallback_keys) = self.account.keys_for_upload().await;

        let device_keys = device_keys
            .expect("We should always try to upload device keys for a dehydrated device.")
            .to_raw();

        trace!("Creating a upload request for a dehydrated device");

        let device_id = self.account.device_id().to_owned();
        let device_data = self.account.dehydrate(pickle_key).await;

        assign!(put_dehydrated_device::unstable::Request::new(device_id, initial_device_display_name, device_data, device_keys), {
            one_time_keys, fallback_keys
        })
    }
}

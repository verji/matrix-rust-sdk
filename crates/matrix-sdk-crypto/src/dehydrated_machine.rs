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

use crate::{
    olm::{Account, PrivateCrossSigningIdentity},
    store::{IntoCryptoStore, MemoryStore, Store},
    verification::VerificationMachine,
    CryptoStoreError, OlmError, OlmMachine, ReadOnlyAccount,
};

pub struct DehydrationMachine {
    inner: OlmMachine,
}

impl DehydrationMachine {
    pub fn create(&self) -> DehydratedAccount {
        DehydratedAccount::new(self.inner.user_id(), self.inner.store().private_identity())
    }
}

pub struct RehydratedMachine {
    dehydrated: OlmMachine,
    original: OlmMachine,
}

impl RehydratedMachine {
    pub(crate) fn new(target: OlmMachine, device_id: &DeviceId, dehydrated_pickle: String) -> Self {
        todo!()
    }

    pub async fn receive_events(&self, events: Vec<Raw<AnyToDeviceEvent>>) -> Result<(), OlmError> {
        // TODO: Intercept the room keys and store them in the `original` `OlmMachine`.

        self.dehydrated
            .receive_sync_changes(events, &Default::default(), &Default::default(), None)
            .await?;

        Ok(())
    }
}

pub struct DehydratedAccount {
    account: Account,
}

impl DehydratedAccount {
    pub fn new(user_id: &UserId, user_identity: Arc<Mutex<PrivateCrossSigningIdentity>>) -> Self {
        let account = ReadOnlyAccount::new(user_id);
        let store = MemoryStore::new().into_crypto_store();

        let verification_machine =
            VerificationMachine::new(account.clone(), user_identity.clone(), store.clone());
        let store = Store::new(user_id.into(), user_identity, store, verification_machine);

        let account = Account { inner: account, store };

        Self { account }
    }

    pub async fn keys_for_upload(
        &self,
        initial_device_display_name: String,
        pickle_key: &[u8],
    ) -> put_dehydrated_device::unstable::Request {
        let (device_keys, one_time_keys, fallback_keys) = self.account.keys_for_upload().await;

        let device_keys = device_keys
            .expect("We should always upload device keys for a dehydrated device.")
            .to_raw();

        let device_id = self.account.device_id().to_owned();
        let devicd_data = self.get_device_data(pickle_key).await;

        assign!(put_dehydrated_device::unstable::Request::new(device_id, initial_device_display_name, devicd_data, device_keys), {
            one_time_keys, fallback_keys
        })
    }

    pub async fn get_device_data(&self, pickle_key: &[u8]) -> Raw<DehydratedDeviceData> {
        todo!()
    }
}

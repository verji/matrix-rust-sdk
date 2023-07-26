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

use ruma::{api::client::dehydrated_device, assign, OwnedDeviceId};

use crate::{Client, Result};

pub struct DehydratedDevices {
    pub(super) inner: matrix_sdk_base::crypto::dehydrated_machine::DehydratedDevices,
    pub(super) client: Client,
}

impl DehydratedDevices {
    const DEVICE_DISPLAY_NAME: &str = "Dehydrated device";

    pub async fn create(&self, pickle_key: &[u8; 32]) -> Result<()> {
        let account = self.inner.create();

        let request =
            account.keys_for_upload(Self::DEVICE_DISPLAY_NAME.to_owned(), pickle_key).await?;

        self.client.send(request, Default::default()).await?;

        Ok(())
    }

    async fn get_dehydrated_device(
        &self,
    ) -> Result<dehydrated_device::get_dehydrated_device::unstable::Response> {
        let request = dehydrated_device::get_dehydrated_device::unstable::Request::new();
        Ok(self.client.send(request, Default::default()).await?)
    }

    async fn get_events(
        &self,
        device_id: OwnedDeviceId,
        since: Option<String>,
    ) -> Result<dehydrated_device::get_events::unstable::Response> {
        let request = assign!(dehydrated_device::get_events::unstable::Request::new(device_id), {
            since: since
        });

        Ok(self.client.send(request, Default::default()).await?)
    }

    pub async fn rehydrate(&self, pickle_key: &[u8; 32]) -> Result<usize> {
        let response = self.get_dehydrated_device().await?;

        let rehydrated_machine =
            self.inner.rehydrate(pickle_key, &response.device_id, response.device_data).await?;

        let mut since_token = None;
        let mut imported_room_keys = 0;

        loop {
            let events_response =
                self.get_events(response.device_id.to_owned(), since_token).await?;

            if events_response.events.is_empty() {
                break;
            }

            since_token = Some(events_response.next_batch);
            imported_room_keys += rehydrated_machine.receive_events(events_response.events).await?;
        }

        Ok(imported_room_keys)
    }
}

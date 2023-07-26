use std::{mem::ManuallyDrop, sync::Arc};

use matrix_sdk_crypto::dehydrated_machine::{
    DehydratedDevice as InnerDehydratedDevice, DehydratedDevices as InnerDehydratedDevices,
    RehydratedDevice as InnerRehydratedDevice,
};
use ruma::{api::client::dehydrated_device, events::AnyToDeviceEvent, serde::Raw, OwnedDeviceId};
use serde_json::json;
use tokio::runtime::Handle;
use zeroize::Zeroize;

#[derive(uniffi::Object)]
pub struct DehydratedDevices {
    pub(crate) runtime: Handle,
    pub(crate) inner: ManuallyDrop<InnerDehydratedDevices>,
}

impl Drop for DehydratedDevices {
    fn drop(&mut self) {
        // See the drop implementation for the `crate::OlmMachine` for an explanation.
        let inner = unsafe { ManuallyDrop::take(&mut self.inner) };
        let _guard = self.runtime.enter();
        drop(inner);
    }
}

#[uniffi::export]
impl DehydratedDevices {
    pub fn create(&self) -> Arc<DehydratedDevice> {
        DehydratedDevice {
            inner: ManuallyDrop::new(self.inner.create()),
            runtime: self.runtime.to_owned(),
        }
        .into()
    }

    pub fn rehydrate(
        &self,
        pickle_key: Vec<u8>,
        device_id: String,
        device_data: String,
    ) -> Arc<RehydratedDevice> {
        let device_data: Raw<_> = serde_json::from_str(&device_data).unwrap();
        let device_id: OwnedDeviceId = device_id.into();
        let mut key: [u8; 32] = pickle_key.try_into().unwrap();

        let ret = RehydratedDevice {
            runtime: self.runtime.to_owned(),
            inner: ManuallyDrop::new(
                self.runtime.block_on(self.inner.rehydrate(&key, &device_id, device_data)).unwrap(),
            ),
        }
        .into();

        key.zeroize();

        ret
    }
}

#[derive(uniffi::Object)]
pub struct RehydratedDevice {
    inner: ManuallyDrop<InnerRehydratedDevice>,
    runtime: Handle,
}

impl Drop for RehydratedDevice {
    fn drop(&mut self) {
        // See the drop implementation for the `crate::OlmMachine` for an explanation.
        let inner = unsafe { ManuallyDrop::take(&mut self.inner) };
        let _guard = self.runtime.enter();
        drop(inner);
    }
}

#[uniffi::export]
impl RehydratedDevice {
    pub fn receive_events(&self, events: String) {
        let events: Vec<Raw<AnyToDeviceEvent>> = serde_json::from_str(&events).unwrap();
        self.runtime.block_on(self.inner.receive_events(events)).unwrap();
    }
}

#[derive(uniffi::Object)]
pub struct DehydratedDevice {
    pub(crate) runtime: Handle,
    pub(crate) inner: ManuallyDrop<InnerDehydratedDevice>,
}

impl Drop for DehydratedDevice {
    fn drop(&mut self) {
        // See the drop implementation for the `crate::OlmMachine` for an explanation.
        let inner = unsafe { ManuallyDrop::take(&mut self.inner) };
        let _guard = self.runtime.enter();
        drop(inner);
    }
}

#[uniffi::export]
impl DehydratedDevice {
    pub fn keys_for_upload(
        &self,
        device_display_name: String,
        pickle_key: Vec<u8>,
    ) -> UploadDehydratedDeviceRequest {
        let mut key: [u8; 32] = pickle_key.try_into().unwrap();

        let request =
            self.runtime.block_on(self.inner.keys_for_upload(device_display_name, &key)).unwrap();

        key.zeroize();

        request.into()
    }
}

#[derive(Debug, uniffi::Record)]
pub struct UploadDehydratedDeviceRequest {
    /// The serialized JSON body of the request.
    body: String,
}

impl From<dehydrated_device::put_dehydrated_device::unstable::Request>
    for UploadDehydratedDeviceRequest
{
    fn from(value: dehydrated_device::put_dehydrated_device::unstable::Request) -> Self {
        let body = json!({
            "device_id": value.device_id,
            "device_data": value.device_data,
            "initial_device_display_name": value.initial_device_display_name,
            "device_keys": value.device_keys,
            "one_time_keys": value.one_time_keys,
            "fallback_keys": value.fallback_keys,
        });

        let body = serde_json::to_string(&body)
            .expect("We should be able to serialize the PUT dehydrated devices request body");

        Self { body }
    }
}

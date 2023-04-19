use ruma::OwnedDeviceId;
use serde::{Deserialize, Serialize};
use vodozemac::{megolm::MegolmMessage, Curve25519PublicKey};

use crate::types::{deserialize_curve_key, serialize_curve_key};

/// The event content for events encrypted with the m.megolm.v1.aes-sha2
/// algorithm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MegolmV1AesSha2Content {
    /// The encrypted content of the event.
    pub ciphertext: MegolmMessage,

    /// The Curve25519 key of the sender.
    #[serde(deserialize_with = "deserialize_curve_key", serialize_with = "serialize_curve_key")]
    pub sender_key: Curve25519PublicKey,

    /// The ID of the sending device.
    pub device_id: OwnedDeviceId,

    /// The ID of the session used to encrypt the message.
    pub session_id: String,
}

/// The event content for events encrypted with the m.megolm.v2.aes-sha2
/// algorithm.
#[cfg(feature = "experimental-algorithms")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MegolmV2AesSha2Content {
    /// The encrypted content of the event.
    pub ciphertext: MegolmMessage,

    /// The ID of the session used to encrypt the message.
    pub session_id: String,
}

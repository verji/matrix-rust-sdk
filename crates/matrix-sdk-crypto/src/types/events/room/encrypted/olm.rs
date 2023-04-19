use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use vodozemac::{olm::OlmMessage, Curve25519PublicKey};

use crate::types::{deserialize_curve_key, serialize_curve_key};

/// The event content for events encrypted with the m.olm.v1.curve25519-aes-sha2
/// algorithm.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "OlmHelper")]
pub struct OlmV1Curve25519AesSha2Content {
    /// The encrypted content of the event.
    pub ciphertext: OlmMessage,

    /// The Curve25519 key of the recipient device.
    pub recipient_key: Curve25519PublicKey,

    /// The Curve25519 key of the sender.
    pub sender_key: Curve25519PublicKey,
}

/// The event content for the experimental org.matrix.olm.curve25519-aes-sha2-protobuf algorithm.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct OlmCurve25519AesSha2ProtobufContent {}

/// The event content for events encrypted with the m.olm.v2.curve25519-aes-sha2
/// algorithm.
#[cfg(feature = "experimental-algorithms")]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct OlmV2Curve25519AesSha2Content {
    /// The encrypted content of the event.
    pub ciphertext: OlmMessage,

    /// The Curve25519 key of the sender.
    #[serde(deserialize_with = "deserialize_curve_key", serialize_with = "serialize_curve_key")]
    pub sender_key: Curve25519PublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
struct OlmHelper {
    #[serde(deserialize_with = "deserialize_curve_key", serialize_with = "serialize_curve_key")]
    sender_key: Curve25519PublicKey,
    ciphertext: BTreeMap<String, OlmMessage>,
}

impl Serialize for OlmV1Curve25519AesSha2Content {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let ciphertext =
            BTreeMap::from([(self.recipient_key.to_base64(), self.ciphertext.clone())]);

        OlmHelper { sender_key: self.sender_key, ciphertext }.serialize(serializer)
    }
}

impl TryFrom<OlmHelper> for OlmV1Curve25519AesSha2Content {
    type Error = serde_json::Error;

    fn try_from(value: OlmHelper) -> Result<Self, Self::Error> {
        let (recipient_key, ciphertext) = value.ciphertext.into_iter().next().ok_or_else(|| {
            serde::de::Error::custom(
                "The `m.room.encrypted` event is missing a ciphertext".to_owned(),
            )
        })?;

        let recipient_key =
            Curve25519PublicKey::from_base64(&recipient_key).map_err(serde::de::Error::custom)?;

        Ok(Self { ciphertext, recipient_key, sender_key: value.sender_key })
    }
}

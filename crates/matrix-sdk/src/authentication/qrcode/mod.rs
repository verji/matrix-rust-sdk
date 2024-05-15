// Copyright 2024 The Matrix.org Foundation C.I.C.
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

#![allow(missing_docs)]

use matrix_sdk_base::crypto::SecretImportError;
use openidconnect::{
    core::CoreErrorResponseType, ConfigurationError, DeviceCodeErrorResponseType, DiscoveryError,
    HttpClientError, RequestTokenError, StandardErrorResponse,
};
use thiserror::Error;
pub use vodozemac::ecies::{Error as EciesError, MessageDecodeError};

use crate::{oidc::CrossProcessRefreshLockError, HttpError};

mod grant_login;
mod login;
mod messages;
mod rendezvous_channel;
mod secure_channel;

pub use grant_login::ExistingAuthGrantDings;
pub use login::{LoginProgress, LoginWithQrCode};
pub use matrix_sdk_base::crypto::types::qr_login::QrCodeData;

use self::messages::QrAuthMessage;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Oidc(#[from] DeviceAuhorizationOidcError),

    #[error(transparent)]
    SessionTokens(crate::Error),

    #[error(transparent)]
    UserIdDiscovery(HttpError),

    #[error(transparent)]
    SecretImport(#[from] SecretImportError),

    #[error("We have received an unexpected message, expected: {expected}, got {received:?}.")]
    UnexpectedMessage { expected: &'static str, received: QrAuthMessage },

    #[error(transparent)]
    CrossProcessRefreshLock(#[from] CrossProcessRefreshLockError),

    #[error(transparent)]
    SecureChannel(#[from] SecureChannelError),

    #[error(transparent)]
    DeviceKeyUpload(crate::Error),
}

#[derive(Debug, Error)]
pub enum DeviceAuhorizationOidcError {
    #[error(transparent)]
    Oidc(#[from] crate::oidc::OidcError),

    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    #[error(transparent)]
    Configuration(#[from] ConfigurationError),

    #[error(transparent)]
    AuthenticationIssuer(HttpError),

    #[error(transparent)]
    DeviceAuthorization(
        #[from]
        RequestTokenError<
            HttpClientError<reqwest::Error>,
            StandardErrorResponse<CoreErrorResponseType>,
        >,
    ),

    #[error(transparent)]
    RequestToken(
        #[from]
        RequestTokenError<
            HttpClientError<reqwest::Error>,
            StandardErrorResponse<DeviceCodeErrorResponseType>,
        >,
    ),

    #[error(transparent)]
    Discovery(#[from] DiscoveryError<HttpClientError<reqwest::Error>>),
}

#[derive(Debug, Error)]
pub enum SecureChannelError {
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error(transparent)]
    Ecies(#[from] EciesError),

    #[error(transparent)]
    MessageDecode(#[from] MessageDecodeError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(
        "The secure setup has received an unexpected message, expected: {expected}, got {got}."
    )]
    SecureChannelMessage { expected: &'static str, got: String },

    #[error("The secure channel could not have been established, the check code was invalid.")]
    InvalidCheckCode,

    #[error(transparent)]
    RendezvousChannel(#[from] HttpError),

    #[error("The secure channel could not have been established, the two devices have the same login intent.")]
    InvalidIntent,
}

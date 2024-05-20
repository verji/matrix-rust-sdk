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

use std::{future::IntoFuture, pin::Pin};

use eyeball::SharedObservable;
use futures_core::{Future, Stream};
use mas_oidc_client::types::{
    client_credentials::ClientCredentials,
    registration::VerifiedClientMetadata,
    scope::{MatrixApiScopeToken, ScopeToken},
};
use matrix_sdk_base::{
    boxed_into_future,
    crypto::types::qr_login::{QrCodeData, QrCodeMode},
    SessionMeta,
};
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreClaimName, CoreClaimType, CoreClient,
        CoreClientAuthMethod, CoreDeviceAuthorizationResponse, CoreErrorResponseType,
        CoreGenderClaim, CoreGrantType, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm, CoreResponseMode, CoreResponseType, CoreRevocableToken,
        CoreRevocationErrorResponse, CoreSubjectIdentifierType, CoreTokenIntrospectionResponse,
        CoreTokenResponse,
    },
    AdditionalProviderMetadata, AuthType, ClientId, ClientSecret, DeviceAuthorizationUrl,
    DeviceCodeErrorResponseType, EmptyAdditionalClaims, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, HttpClientError, IssuerUrl, OAuth2TokenResponse, ProviderMetadata, Scope,
    StandardErrorResponse,
};
use ruma::OwnedDeviceId;
use vodozemac::{ecies::CheckCode, Curve25519PublicKey};

use super::{messages::LoginFailureReason, DeviceAuhorizationOidcError, SecureChannelError};
use crate::{
    authentication::qrcode::{
        messages::QrAuthMessage, secure_channel::EstablishedSecureChannel, QRCodeLoginError,
    },
    http_client::HttpClient,
    oidc::OidcSessionTokens,
    Client,
};

// Obtain the device_authorization_url from the OIDC metadata provider.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct DeviceEndpointProviderMetadata {
    device_authorization_endpoint: DeviceAuthorizationUrl,
}
impl AdditionalProviderMetadata for DeviceEndpointProviderMetadata {}

type DeviceProviderMetadata = ProviderMetadata<
    DeviceEndpointProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

/// OpenID Connect Core client.
pub type OidcClientInner<
    HasAuthUrl = EndpointSet,
    HasDeviceAuthUrl = EndpointSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointMaybeSet,
    HasUserInfoUrl = EndpointMaybeSet,
> = openidconnect::Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    CoreTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
    HasUserInfoUrl,
>;

pub struct OidcClient {
    inner: OidcClientInner,
    http_client: HttpClient,
}

impl OidcClient {
    async fn request_device_authorization(
        &self,
        device_id: Curve25519PublicKey,
    ) -> Result<CoreDeviceAuthorizationResponse, DeviceAuhorizationOidcError> {
        let scopes = [
            ScopeToken::Openid,
            ScopeToken::MatrixApi(MatrixApiScopeToken::Full),
            ScopeToken::try_with_matrix_device(device_id.to_base64()).expect(
                "We should be able to create a scope token from a \
                 Curve25519 public key encoded as base64",
            ),
        ]
        .into_iter()
        .map(|scope| Scope::new(scope.to_string()));

        let details: CoreDeviceAuthorizationResponse = self
            .inner
            .exchange_device_code()
            .add_scopes(scopes)
            .request_async(&self.http_client)
            .await?;

        Ok(details)
    }

    async fn wait_for_tokens(
        &self,
        details: &CoreDeviceAuthorizationResponse,
    ) -> Result<OidcSessionTokens, DeviceAuhorizationOidcError> {
        let response = self
            .inner
            .exchange_device_access_token(&details)?
            .request_async(&self.http_client, tokio::time::sleep, None)
            .await?;

        let tokens = OidcSessionTokens {
            access_token: response.access_token().secret().to_owned(),
            refresh_token: response.refresh_token().map(|t| t.secret().to_owned()),
            // TODO: How do we convert this into the appropriate type?
            // latest_id_token: response.id_token(),
            latest_id_token: None,
        };

        Ok(tokens)
    }
}

#[derive(Clone, Debug, Default)]
pub enum LoginProgress {
    #[default]
    Starting,
    EstablishingSecureChannel {
        check_code: CheckCode,
    },
    WaitingForToken {
        user_code: String,
    },
    Done,
}

async fn send_unexpected_message_error(
    channel: &mut EstablishedSecureChannel,
) -> Result<(), SecureChannelError> {
    channel
        .send_json(QrAuthMessage::LoginFailure {
            reason: LoginFailureReason::UnexpectedMessageReceived,
            homeserver: None,
        })
        .await
}

/// Named future for the [`Backups::wait_for_steady_state()`] method.
#[derive(Debug)]
pub struct LoginWithQrCode<'a> {
    client: &'a Client,
    client_metadata: VerifiedClientMetadata,
    qr_code_data: &'a QrCodeData,
    state: SharedObservable<LoginProgress>,
}

impl<'a> LoginWithQrCode<'a> {
    /// Subscribe to the progress of the backup upload step while waiting for it
    /// to settle down.
    pub fn subscribe_to_progress(&self) -> impl Stream<Item = LoginProgress> {
        self.state.subscribe()
    }
}

impl<'a> IntoFuture for LoginWithQrCode<'a> {
    type Output = Result<(), QRCodeLoginError>;
    boxed_into_future!(extra_bounds: 'a);

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            // First things first establish the secure channel, since we're the one that
            // scanned the QR code, we're certain that the secure channel is
            // secure.
            let mut channel = self.establish_channel().await?;

            // The other side isn't yet sure that it's talking to the right device, show
            // a check code so they can confirm.
            let check_code = channel.check_code().to_owned();
            self.state.set(LoginProgress::EstablishingSecureChannel { check_code });

            // Register the client with the OIDC provider.
            let oidc_client = self.register_client().await?;

            // We want to use the Curve25519 public key for the device ID, so let's generate
            // a new vodozemac `Account` now.
            let account = vodozemac::olm::Account::new();
            let public_key = account.identity_keys().curve25519;
            let device_id = public_key;

            // Let's tell the OIDC provider that we want to log in using the device
            // authorization grant described in [RFC8628](https://datatracker.ietf.org/doc/html/rfc8628).
            let auth_grant_response = oidc_client.request_device_authorization(device_id).await?;

            // Now we need to inform the other device of the login protocols we picked and
            // the URL they should use to log us in.
            let message = QrAuthMessage::login_protocols((&auth_grant_response).into(), device_id);
            channel.send_json(&message).await?;

            // Let's see if the other device agreed to our proposed protocols.
            match channel.receive_json().await? {
                QrAuthMessage::LoginProtocolAccepted {} => (),
                QrAuthMessage::LoginFailure { reason, homeserver } => {
                    return Err(QRCodeLoginError::LoginFailure { reason, homeserver });
                }
                message => {
                    send_unexpected_message_error(&mut channel).await?;

                    return Err(QRCodeLoginError::UnexpectedMessage {
                        expected: "m.login.protocol_accepted",
                        received: message,
                    });
                }
            }

            // The OIDC provider may or may not show this user code to double check that
            // we're talking to the right OIDC provider. Let us display this, so
            // the other device can double check this as well.
            let user_code = auth_grant_response.user_code();
            self.state
                .set(LoginProgress::WaitingForToken { user_code: user_code.secret().to_owned() });

            // Let's now wait for the access token to be provided to use by the OIDC
            // provider.
            let session_tokens = match oidc_client.wait_for_tokens(&auth_grant_response).await {
                Ok(t) => t,
                Err(e) => {
                    // If we received an error, and it's one of the ones we should report to the
                    // other side, do so now.
                    if let Some(e) = e.as_request_token_error() {
                        match e {
                            DeviceCodeErrorResponseType::AccessDenied => {
                                channel.send_json(QrAuthMessage::LoginDeclined {}).await?;
                            }
                            DeviceCodeErrorResponseType::ExpiredToken => {
                                channel
                                    .send_json(QrAuthMessage::LoginFailure {
                                        reason: LoginFailureReason::AuthorizationExpired,
                                        homeserver: None,
                                    })
                                    .await?;
                            }
                            _ => (),
                        }
                    }

                    return Err(e.into());
                }
            };
            self.client.oidc().set_session_tokens(session_tokens);

            // We only received an access token from the OIDC provider, we have no clue who
            // we are, so we need to figure out our user ID now.
            // TODO: This snippet is almost the same as the Oidc::finish_login_method(), why
            // is that method even a public method and not called as part of the set session
            // tokens method.
            let whoami_response =
                self.client.whoami().await.map_err(QRCodeLoginError::UserIdDiscovery)?;
            self.client
                .set_session_meta(
                    SessionMeta {
                        user_id: whoami_response.user_id,
                        device_id: OwnedDeviceId::from(device_id.to_base64()),
                    },
                    Some(account),
                )
                .await
                .map_err(QRCodeLoginError::SessionTokens)?;

            self.client.oidc().enable_cross_process_lock().await?;

            // Tell the existing device that we're logged in.
            let message = QrAuthMessage::LoginSuccess {};
            channel.send_json(&message).await?;

            // Let's wait for the secrets bundle to be sent to us, otherwise we won't be a
            // fully E2EE enabled device.
            let bundle = match channel.receive_json().await? {
                QrAuthMessage::LoginSecrets(bundle) => bundle,
                QrAuthMessage::LoginFailure { reason, homeserver } => {
                    return Err(QRCodeLoginError::LoginFailure { reason, homeserver });
                }
                message => {
                    send_unexpected_message_error(&mut channel).await?;

                    return Err(QRCodeLoginError::UnexpectedMessage {
                        expected: "m.login.protocol_accepted",
                        received: message,
                    });
                }
            };

            // Import the secrets bundle, this will allow us to sign the device keys with
            // the master key when we upload them.
            self.client.encryption().import_secrets_bundle(&bundle).await?;

            // Upload the device keys, this will ensure that other devices see us as a fully
            // verified device ass soon as this method returns.
            self.client
                .encryption()
                .ensure_device_keys_upload()
                .await
                .map_err(QRCodeLoginError::DeviceKeyUpload)?;

            // Run and wait for the E2EE initialization tasks, this will ensure that we
            // ourselves see us as verified and the recovery/backup states will
            // be known. If we did receive all the secrets in the secrets
            // bundle, then backups will be enabled after this step as well.
            self.client.encryption().run_initialization_tasks(None).await;
            self.client.encryption().wait_for_e2ee_initialization_tasks().await;

            // Tell our listener that we're done.
            self.state.set(LoginProgress::Done);

            // And indeed, we are done with the login.
            Ok(())
        })
    }
}

impl<'c> openidconnect::AsyncHttpClient<'c> for HttpClient {
    type Error = HttpClientError<reqwest::Error>;

    type Future = Pin<
        Box<
            dyn Future<Output = Result<openidconnect::HttpResponse, Self::Error>>
                + Send
                + Sync
                + 'c,
        >,
    >;

    fn call(&'c self, request: openidconnect::HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response = self.inner.call(request).await?;

            Ok(response)
        })
    }
}

impl<'a> LoginWithQrCode<'a> {
    pub(crate) fn new(
        client: &'a Client,
        client_metadata: VerifiedClientMetadata,
        qr_code_data: &'a QrCodeData,
    ) -> LoginWithQrCode<'a> {
        LoginWithQrCode { client, client_metadata, qr_code_data, state: Default::default() }
    }

    async fn establish_channel(&self) -> Result<EstablishedSecureChannel, SecureChannelError> {
        let http_client = self.client.inner.http_client.inner.clone();

        let channel = EstablishedSecureChannel::from_qr_code(
            http_client,
            &self.qr_code_data,
            QrCodeMode::Login,
        )
        .await?;

        Ok(channel)
    }

    async fn register_client(&self) -> Result<OidcClient, DeviceAuhorizationOidcError> {
        // Let's figure out the OIDC issuer, this fetches the info from the homeserver.
        let issuer = self
            .client
            .oidc()
            .fetch_authentication_issuer()
            .await
            .map_err(DeviceAuhorizationOidcError::AuthenticationIssuer)?;

        // Now we register the client with the OIDC provider.
        let registration_response =
            self.client.oidc().register_client(&issuer, self.client_metadata.clone(), None).await?;

        let client_secret = registration_response.client_secret.map(ClientSecret::new);
        let client_id = ClientId::new(registration_response.client_id);
        let issuer_url = IssuerUrl::new(issuer.clone())?;

        // Now we need to put the relevant data we got from the regustration response
        // into the `Client`.
        // TODO: Why isn't `oidc().register_client()` doing this automatically?
        self.client.oidc().restore_registered_client(
            issuer,
            self.client_metadata.clone(),
            ClientCredentials::None { client_id: client_id.as_str().to_owned() },
        );

        // We're now switching to the openidconnect crate, it has a bit of a strange API
        // where you need to provide the HTTP client in every call you make.
        let http_client = self.client.inner.http_client.clone();

        // We're fetching the provider metadata which will contain the device
        // authorization endpoint. We can use this endpoint to attempt to log in
        // this new device, though the other, existing device will do that using the
        // verification URL.
        let provider_metadata =
            DeviceProviderMetadata::discover_async(issuer_url, &http_client).await?;
        let device_authorization_endpoint =
            provider_metadata.additional_metadata().device_authorization_endpoint.clone();

        let oidc_client =
            CoreClient::from_provider_metadata(provider_metadata, client_id.clone(), client_secret)
                .set_device_authorization_url(device_authorization_endpoint)
                .set_auth_type(AuthType::RequestBody);

        Ok(OidcClient { inner: oidc_client, http_client })
    }
}

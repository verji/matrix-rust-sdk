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

use std::{future::IntoFuture, pin::Pin, str::FromStr};

use eyeball::SharedObservable;
use futures_core::{Future, Stream};
use http::Method;
use mas_oidc_client::types::{
    client_credentials::ClientCredentials,
    registration::VerifiedClientMetadata,
    scope::{MatrixApiScopeToken, ScopeToken},
};
use matrix_sdk_base::{
    boxed_into_future,
    crypto::qr_login::{QrCodeData, QrCodeMode},
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
    EmptyAdditionalClaims, EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl,
    OAuth2TokenResponse, ProviderMetadata, Scope, StandardErrorResponse,
};
use ruma::{api::client::discovery::discover_homeserver::AuthenticationServerInfo, OwnedDeviceId};
use url::Url;
use vodozemac::{secure_channel::CheckCode, Curve25519PublicKey, Curve25519SecretKey};

use crate::{
    authentication::qrcode::{
        messages::QrAuthMessage, secure_channel::EstablishedSecureChannel, Error,
    },
    http_client::HttpClient,
    oidc::OidcSessionTokens,
    Client, HttpError,
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
    http_client: openidconnect::reqwest::Client,
}

impl OidcClient {
    async fn request_device_authorization(
        &self,
        device_id: Curve25519PublicKey,
    ) -> Result<CoreDeviceAuthorizationResponse, Error> {
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
            .await
            .unwrap();

        Ok(details)
    }

    async fn wait_for_tokens(
        &self,
        details: &CoreDeviceAuthorizationResponse,
    ) -> Result<OidcSessionTokens, Error> {
        let response = self
            .inner
            .exchange_device_access_token(&details)
            .unwrap()
            .request_async(&self.http_client, tokio::time::sleep, None)
            .await
            .unwrap();

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
    type Output = Result<(), Error>;
    boxed_into_future!(extra_bounds: 'a);

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let mut channel = self.establish_channel().await?;

            let check_code = channel.check_code().to_owned();
            self.state.set(LoginProgress::EstablishingSecureChannel { check_code });

            let oidc_client = self.register_client().await?;

            let account = vodozemac::olm::Account::new();
            let public_key = account.identity_keys().curve25519;
            let device_id = public_key;

            let auth_grant_response = oidc_client.request_device_authorization(device_id).await?;

            let message = QrAuthMessage::login_protocols((&auth_grant_response).into(), device_id);
            channel.send_json(&message).await?;

            let message = channel.receive_json().await?;
            let QrAuthMessage::LoginProtocolAccepted {} = message else {
                return Err(Error::UnexpectedMessage {
                    expected: "m.login.protocol_accepted",
                    received: message,
                });
            };

            let user_code = auth_grant_response.user_code();

            self.state
                .set(LoginProgress::WaitingForToken { user_code: user_code.secret().to_owned() });

            let session_tokens = oidc_client.wait_for_tokens(&auth_grant_response).await?;
            self.client.oidc().set_session_tokens(session_tokens);

            // TODO: This snippet is almost the same as the Oidc::finish_login_method(), why
            // is that method even a public method and not called as part of the set session
            // tokens method.
            let whoami_response = self.client.whoami().await?;
            self.client
                .set_session_meta(
                    SessionMeta {
                        user_id: whoami_response.user_id,
                        device_id: OwnedDeviceId::from(device_id.to_base64()),
                    },
                    Some(account),
                )
                .await
                .unwrap();

            self.client.oidc().enable_cross_process_lock().await.unwrap();

            // Tell the existing device that we're logged in.
            let message = QrAuthMessage::LoginSuccess {};
            channel.send_json(&message).await?;

            let message = channel.receive_json().await?;
            let QrAuthMessage::LoginSecrets(bundle) = message else {
                return Err(Error::UnexpectedMessage {
                    expected: "m.login.secrets",
                    received: message,
                });
            };

            // Upload the device keys and stuff.
            self.client.encryption().import_secrets_bundle(&bundle).await?;
            self.client.encryption().ensure_device_keys_upload().await.unwrap();
            self.client.encryption().run_initialization_tasks(None).await.unwrap();
            self.client.encryption().wait_for_e2ee_initialization_tasks().await;

            self.state.set(LoginProgress::Done);

            Ok(())
        })
    }
}

impl<'c> openidconnect::AsyncHttpClient<'c> for HttpClient {
    type Error = Error;

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
            let url = Url::parse(&request.uri().to_string()).unwrap();
            let method = Method::from_str(request.method().as_str()).unwrap();

            let response = self.inner.request(method, url).send().await.unwrap();

            let mut builder =
                openidconnect::http::Response::builder().status(response.status().as_u16());

            for (name, value) in response.headers().iter() {
                builder = builder.header(name.as_str(), value.as_bytes());
            }

            let body = response.bytes().await.unwrap().to_vec();
            let response = builder.body(body).unwrap();

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

    async fn establish_channel(&self) -> Result<EstablishedSecureChannel, Error> {
        let http_client = self.client.inner.http_client.inner.clone();

        let channel = EstablishedSecureChannel::from_qr_code(
            http_client,
            &self.qr_code_data,
            QrCodeMode::Login,
        )
        .await?;

        Ok(channel)
    }

    async fn register_client(&self) -> Result<OidcClient, Error> {
        // Let's figure out the OIDC issuer, this fetches the info from the homeserver.
        let issuer = self.client.oidc().fetch_authentication_issuer().await.unwrap();
        // TODO: How do I get the account management URL.
        let issuer_info = AuthenticationServerInfo::new(issuer, None);

        let registration_response = self
            .client
            .oidc()
            .register_client(&issuer_info.issuer, self.client_metadata.clone(), None)
            .await
            .unwrap();

        let client_secret = registration_response.client_secret.map(ClientSecret::new);
        let client_id = ClientId::new(registration_response.client_id);
        let issuer_url = IssuerUrl::new(issuer_info.issuer.clone())?;

        // Let's put the relevant data we got from the `register_client()` request into
        // the `Client`, why isn't `register_client()` doing this automagically?
        self.client.oidc().restore_registered_client(
            issuer_info,
            self.client_metadata.clone(),
            ClientCredentials::None { client_id: client_id.as_str().to_owned() },
        );

        // let http_client = self.client.inner.http_client.clone();
        let http_client = openidconnect::reqwest::Client::builder()
            // .proxy(Proxy::all("http://localhost:8011").unwrap())
            // .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let provider_metadata =
            DeviceProviderMetadata::discover_async(issuer_url, &http_client).await.unwrap();

        let device_authorization_endpoint =
            provider_metadata.additional_metadata().device_authorization_endpoint.clone();

        let oidc_client =
            CoreClient::from_provider_metadata(provider_metadata, client_id.clone(), client_secret)
                .set_device_authorization_url(device_authorization_endpoint)
                .set_auth_type(AuthType::RequestBody);

        Ok(OidcClient { inner: oidc_client, http_client })
    }
}

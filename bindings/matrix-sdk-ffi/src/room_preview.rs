// Copyright 2025 The Matrix.org Foundation C.I.C.
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
// See the License for that specific language governing permissions and
// limitations under the License.

use anyhow::Context as _;
use matrix_sdk::{Client, room_preview::RoomPreview as SdkRoomPreview};
use ruma::room::{JoinRuleSummary, RoomType as RumaRoomType};

use crate::{
    client::{AllowRule, JoinRule},
    error::ClientError,
    room::{InviteSender, Membership, RoomHero},
    room_member::{RoomMember, RoomMemberWithSenderInfo},
    utils::AsyncRuntimeDropped,
};

/// A room preview for a room. It's intended to be used to represent rooms that
/// aren't joined yet.
#[derive(uniffi::Object)]
pub struct RoomPreview {
    inner: SdkRoomPreview,
    client: AsyncRuntimeDropped<Client>,
}

#[matrix_sdk_ffi_macros::export]
impl RoomPreview {
    /// Returns the room info the preview contains.
    pub fn info(&self) -> RoomPreviewInfo {
        let info = &self.inner;
        RoomPreviewInfo {
            room_id: info.room_id.to_string(),
            canonical_alias: info.canonical_alias.as_ref().map(|alias| alias.to_string()),
            name: info.name.clone(),
            topic: info.topic.clone(),
            avatar_url: info.avatar_url.as_ref().map(|url| url.to_string()),
            num_joined_members: info.num_joined_members,
            num_active_members: info.num_active_members,
            room_type: info.room_type.clone().into(),
            is_history_world_readable: info.is_world_readable,
            membership: info.state.map(|state| state.into()),
            join_rule: info.join_rule.clone().map(Into::into),
            is_direct: info.is_direct,
            heroes: info
                .heroes
                .as_ref()
                .map(|heroes| heroes.iter().map(|h| h.to_owned().into()).collect()),
        }
    }

    /// Leave the room if the room preview state is either joined, invited or
    /// knocked.
    ///
    /// If rejecting an invite then also forget it as an extra layer of
    /// protection against spam attacks.
    ///
    /// Will return an error otherwise.
    pub async fn leave(&self) -> Result<(), ClientError> {
        let room =
            self.client.get_room(&self.inner.room_id).context("missing room for a room preview")?;

        Ok(room.leave().await?)
    }

    /// Get the user who created the invite, if any.
    ///
    /// Absent when the sender is not in the stripped state the homeserver sent
    /// with the invitation. Use [`RoomPreview::invite_sender`] to identify them
    /// even in that case.
    pub async fn inviter(&self) -> Option<RoomMember> {
        let room = self.client.get_room(&self.inner.room_id)?;
        let invite_details = room.invite_details().await.ok()?;
        invite_details.inviter.and_then(|m| m.try_into().ok())
    }

    /// Who sent the invitation, when this preview is of an invitation.
    ///
    /// Unlike [`RoomPreview::inviter`], this keeps the sender's user ID when
    /// the member cannot be resolved.
    pub async fn invite_sender(&self) -> Option<InviteSender> {
        let room = self.client.get_room(&self.inner.room_id)?;
        let invite_details = room.invite_details().await.ok()?;
        Some(InviteSender {
            user_id: invite_details.inviter_id.to_string(),
            member: invite_details.inviter.and_then(|m| m.try_into().ok()),
        })
    }

    /// Forget the room if we had access to it, and it was left or banned.
    pub async fn forget(&self) -> Result<(), ClientError> {
        let room =
            self.client.get_room(&self.inner.room_id).context("missing room for a room preview")?;
        room.forget().await?;
        Ok(())
    }

    /// Get the membership details for the current user.
    pub async fn own_membership_details(&self) -> Option<RoomMemberWithSenderInfo> {
        let room = self.client.get_room(&self.inner.room_id)?;
        room.member_with_sender_info(self.client.user_id()?).await.ok()?.try_into().ok()
    }
}

impl RoomPreview {
    pub(crate) fn new(client: AsyncRuntimeDropped<Client>, inner: SdkRoomPreview) -> Self {
        Self { client, inner }
    }
}

/// The preview of a room, be it invited/joined/left, or not.
#[derive(uniffi::Record)]
pub struct RoomPreviewInfo {
    /// The room id for this room.
    pub room_id: String,
    /// The canonical alias for the room.
    pub canonical_alias: Option<String>,
    /// The room's name, if set.
    pub name: Option<String>,
    /// The room's topic, if set.
    pub topic: Option<String>,
    /// The MXC URI to the room's avatar, if set.
    pub avatar_url: Option<String>,
    /// The number of joined members.
    pub num_joined_members: u64,
    /// The number of active members, if known (joined + invited).
    pub num_active_members: Option<u64>,
    /// The room type (space, custom) or nothing, if it's a regular room.
    pub room_type: RoomType,
    /// Is the history world-readable for this room?
    pub is_history_world_readable: Option<bool>,
    /// The membership state for the current user, if known.
    pub membership: Option<Membership>,
    /// The join rule for this room (private, public, knock, etc.).
    pub join_rule: Option<JoinRule>,
    /// Whether the room is direct or not, if known.
    pub is_direct: Option<bool>,
    /// Room heroes.
    pub heroes: Option<Vec<RoomHero>>,
}

impl From<JoinRuleSummary> for JoinRule {
    fn from(join_rule: JoinRuleSummary) -> Self {
        match join_rule {
            JoinRuleSummary::Invite => JoinRule::Invite,
            JoinRuleSummary::Knock => JoinRule::Knock,
            JoinRuleSummary::Private => JoinRule::Private,
            JoinRuleSummary::Restricted(summary) => JoinRule::Restricted {
                rules: summary
                    .allowed_room_ids
                    .iter()
                    .map(|room_id| AllowRule::RoomMembership { room_id: room_id.to_string() })
                    .collect(),
            },
            JoinRuleSummary::KnockRestricted(summary) => JoinRule::KnockRestricted {
                rules: summary
                    .allowed_room_ids
                    .iter()
                    .map(|room_id| AllowRule::RoomMembership { room_id: room_id.to_string() })
                    .collect(),
            },
            JoinRuleSummary::Public => JoinRule::Public,
            _ => JoinRule::Custom { repr: join_rule.as_str().to_owned() },
        }
    }
}

/// The type of room for a [`RoomPreviewInfo`].
#[derive(Debug, Clone, uniffi::Enum)]
pub enum RoomType {
    /// It's a plain chat room.
    Room,
    /// It's a space that can group several rooms.
    Space,
    /// It's a custom implementation.
    Custom { value: String },
}

impl From<Option<RumaRoomType>> for RoomType {
    fn from(value: Option<RumaRoomType>) -> Self {
        match value {
            Some(RumaRoomType::Space) => RoomType::Space,
            Some(RumaRoomType::_Custom(_)) => RoomType::Custom {
                // SAFETY: this was checked in the match branch above
                value: value.unwrap().to_string(),
            },
            _ => RoomType::Room,
        }
    }
}

#[cfg(test)]
mod tests {
    use matrix_sdk::{
        room_preview::RoomPreview as SdkRoomPreview, test_utils::mocks::MatrixMockServer,
    };
    use matrix_sdk_test::InvitedRoomBuilder;
    use ruma::{events::AnyStrippedStateEvent, room_id, serde::Raw};

    use super::RoomPreview;
    use crate::utils::AsyncRuntimeDropped;

    /// A stripped `m.room.member`, as a homeserver sends in `invite_state`.
    fn stripped_member(
        sender: &str,
        state_key: &str,
        membership: &str,
    ) -> Raw<AnyStrippedStateEvent> {
        Raw::from_json_string(
            serde_json::json!({
                "type": "m.room.member",
                "sender": sender,
                "state_key": state_key,
                "content": { "membership": membership },
            })
            .to_string(),
        )
        .unwrap()
    }

    /// A bare preview pointing at a room the client already knows.
    ///
    /// `invite_sender` only reads `room_id` off the preview and then consults
    /// the client's store, so the rest of the preview is irrelevant here.
    fn preview_of(room_id: &ruma::RoomId) -> SdkRoomPreview {
        SdkRoomPreview {
            room_id: room_id.to_owned(),
            canonical_alias: None,
            name: None,
            topic: None,
            avatar_url: None,
            num_joined_members: 0,
            num_active_members: None,
            room_type: None,
            join_rule: None,
            is_world_readable: None,
            state: None,
            is_direct: None,
            heroes: None,
        }
    }

    /// The preview names the sender even when they do not resolve to a member —
    /// the same guarantee `Room::invite_sender` gives, on the other surface.
    #[tokio::test]
    async fn invite_sender_is_named_even_when_the_member_does_not_resolve() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_id = room_id!("!previewed:localhost");

        server
            .sync_room(
                &client,
                InvitedRoomBuilder::new(room_id).add_state_event(stripped_member(
                    "@bob:localhost",
                    "@example:localhost",
                    "invite",
                )),
            )
            .await;

        let preview = RoomPreview::new(AsyncRuntimeDropped::new(client), preview_of(room_id));

        assert!(
            preview.inviter().await.is_none(),
            "the sender is not in the stripped state, so they do not resolve"
        );

        let sender = preview.invite_sender().await.expect("the room is an invitation");
        assert_eq!(sender.user_id, "@bob:localhost", "the sender is still named");
        assert!(sender.member.is_none(), "and still does not resolve");
    }

    /// Both halves are filled, and agree, when the sender resolves.
    #[tokio::test]
    async fn invite_sender_carries_the_member_when_it_resolves() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_id = room_id!("!previewed2:localhost");

        server
            .sync_room(
                &client,
                InvitedRoomBuilder::new(room_id)
                    .add_state_event(stripped_member(
                        "@bob:localhost",
                        "@example:localhost",
                        "invite",
                    ))
                    .add_state_event(stripped_member("@bob:localhost", "@bob:localhost", "join")),
            )
            .await;

        let preview = RoomPreview::new(AsyncRuntimeDropped::new(client), preview_of(room_id));

        let sender = preview.invite_sender().await.expect("the room is an invitation");
        assert_eq!(sender.user_id, "@bob:localhost");
        let member = sender.member.expect("the sender is in the stripped state");
        assert_eq!(member.user_id, "@bob:localhost", "the two halves name the same user");
    }

    /// A room that is not an invitation has no sender to report.
    #[tokio::test]
    async fn invite_sender_is_absent_for_a_joined_room() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let room_id = room_id!("!joined:localhost");

        server.sync_joined_room(&client, room_id).await;

        let preview = RoomPreview::new(AsyncRuntimeDropped::new(client), preview_of(room_id));

        assert!(preview.invite_sender().await.is_none());
    }
}

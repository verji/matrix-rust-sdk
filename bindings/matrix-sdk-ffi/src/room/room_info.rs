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

use std::sync::Arc;

use matrix_sdk::{CallIntentConsensus, EncryptionState, RoomState};
use tracing::warn;

use crate::{
    client::JoinRule,
    error::ClientError,
    notification_settings::RoomNotificationMode,
    room::{
        Membership, RoomHero, RoomHistoryVisibility, SuccessorRoom, power_levels::RoomPowerLevels,
    },
    room_member::RoomMember,
    ruma::RtcCallIntent,
};

#[derive(Clone, uniffi::Enum)]
pub enum RtcCallIntentConsensus {
    Full(RtcCallIntent),
    Partial { intent: RtcCallIntent, agreeing_count: u64, total_count: u64 },
    None,
}

impl From<CallIntentConsensus> for RtcCallIntentConsensus {
    fn from(value: CallIntentConsensus) -> Self {
        match value {
            CallIntentConsensus::Full(intent) => RtcCallIntentConsensus::Full(intent.into()),
            CallIntentConsensus::Partial { intent, agreeing_count, total_count } => {
                RtcCallIntentConsensus::Partial {
                    intent: intent.into(),
                    agreeing_count,
                    total_count,
                }
            }
            CallIntentConsensus::None => RtcCallIntentConsensus::None,
        }
    }
}

#[derive(uniffi::Record)]
pub struct RoomInfo {
    id: String,
    encryption_state: EncryptionState,
    creators: Option<Vec<String>>,
    /// The room's name from the room state event if received from sync, or one
    /// that's been computed otherwise.
    display_name: Option<String>,
    /// Room name as defined by the room state event only.
    raw_name: Option<String>,
    topic: Option<String>,
    avatar_url: Option<String>,
    is_direct: bool,
    is_dm: bool,
    /// Whether the room is public or not, based on the join rules.
    ///
    /// Can be `None` if the join rules state event is not available for this
    /// room.
    is_public: Option<bool>,
    is_space: bool,
    /// If present, it means the room has been archived/upgraded.
    successor_room: Option<SuccessorRoom>,
    is_favourite: bool,
    is_low_priority: bool,
    canonical_alias: Option<String>,
    alternative_aliases: Vec<String>,
    membership: Membership,
    /// User ID of whoever invited the current user, for a room that is in the
    /// invited state.
    ///
    /// Read off the recipient's own membership event, so it is present whenever
    /// that event is in the store — the same condition `inviter` carries. It is
    /// **not** guaranteed merely because the room is an invitation, so callers
    /// must handle its absence.
    ///
    /// Prefer it over `inviter` when the sender only has to be identified — to
    /// ignore them, say. `inviter` has a second, much more common way of being
    /// absent: it is a member-store lookup of that sender, which fails whenever
    /// the homeserver did not include them in the stripped state.
    inviter_id: Option<String>,
    /// Member who invited the current user to a room that's in the invited
    /// state.
    ///
    /// Can be missing if the room membership invite event is missing from the
    /// store, or if the sender is not in the stripped state the homeserver sent
    /// with the invitation. See `inviter_id`.
    inviter: Option<RoomMember>,
    heroes: Vec<RoomHero>,
    active_members_count: u64,
    invited_members_count: u64,
    joined_members_count: u64,
    active_service_members_count: u64,
    service_members: Vec<String>,
    highlight_count: u64,
    notification_count: u64,
    cached_user_defined_notification_mode: Option<RoomNotificationMode>,
    has_room_call: bool,
    active_room_call_participants: Vec<String>,
    active_room_call_consensus_intent: RtcCallIntentConsensus,
    /// Whether this room has been explicitly marked as unread
    is_marked_unread: bool,
    /// "Interesting" messages received in that room, independently of the
    /// notification settings.
    num_unread_messages: u64,
    /// Events that will notify the user, according to their
    /// notification settings.
    num_unread_notifications: u64,
    /// Events causing mentions/highlights for the user, according to their
    /// notification settings.
    num_unread_mentions: u64,
    /// Event ID of the user's `m.fully_read` marker for this room, if any.
    fully_read_event_id: Option<String>,
    /// The currently pinned event ids.
    pinned_event_ids: Vec<String>,
    /// The join rule for this room, if known.
    join_rule: Option<JoinRule>,
    /// The history visibility for this room, if known.
    history_visibility: RoomHistoryVisibility,
    /// This room's current power levels.
    ///
    /// Can be missing if the room power levels event is missing from the store.
    power_levels: Option<Arc<RoomPowerLevels>>,
    /// This room's version.
    room_version: Option<String>,
    /// Whether creators are privileged over every other user (have infinite
    /// power level).
    privileged_creators_role: bool,
}

impl RoomInfo {
    pub(crate) async fn new(room: &matrix_sdk::Room) -> Result<Self, ClientError> {
        let unread_notification_counts = room.unread_notification_counts();

        let pinned_event_ids =
            room.pinned_event_ids().unwrap_or_default().iter().map(|id| id.to_string()).collect();

        let join_rule = room
            .join_rule()
            .map(TryInto::try_into)
            .transpose()
            .inspect_err(|err| {
                warn!("Failed to parse join rule: {err}");
            })
            .ok()
            .flatten();

        let power_levels = room
            .power_levels()
            .await
            .ok()
            .map(|p| RoomPowerLevels::new(p, room.own_user_id().to_owned()));

        // One read of the state feeds both `membership` and the invite fields.
        // Reading it twice around an await let a sync land in between, and the
        // two could then disagree — a `membership` of `Joined` carrying an
        // inviter, or an `Invited` whose inviter was dropped for having been
        // joined a moment ago.
        let state = room.state();

        // Fetched once and split across the two fields below. Note this is the
        // *recipient's* own membership event being read: when it is missing
        // from the store there is no sender to name, so both fields go empty
        // together.
        let invite_details = match state {
            RoomState::Invited => room.invite_details().await.ok(),
            _ => None,
        };

        Ok(Self {
            id: room.room_id().to_string(),
            encryption_state: room.encryption_state(),
            creators: room
                .creators()
                .map(|creators| creators.into_iter().map(Into::into).collect()),
            display_name: room.cached_display_name().map(|name| name.to_string()),
            raw_name: room.name(),
            topic: room.topic(),
            avatar_url: room.avatar_url().map(Into::into),
            is_direct: room.is_direct().await?,
            is_dm: room.compute_is_dm().await?,
            is_public: room.is_public(),
            is_space: room.is_space(),
            successor_room: room.successor_room().map(Into::into),
            is_favourite: room.is_favourite(),
            is_low_priority: room.is_low_priority(),
            canonical_alias: room.canonical_alias().map(Into::into),
            alternative_aliases: room.alt_aliases().into_iter().map(Into::into).collect(),
            membership: state.into(),
            inviter_id: invite_details.as_ref().map(|d| d.inviter_id.to_string()),
            inviter: invite_details
                .and_then(|details| details.inviter)
                .map(TryInto::try_into)
                .transpose()
                .ok()
                .flatten(),
            heroes: room.heroes().into_iter().map(Into::into).collect(),
            active_members_count: room.active_members_count(),
            invited_members_count: room.invited_members_count(),
            joined_members_count: room.joined_members_count(),
            active_service_members_count: room.active_service_members_count().unwrap_or_default(),
            service_members: room
                .service_members()
                .iter()
                .flatten()
                .map(|m| m.to_string())
                .collect(),
            highlight_count: unread_notification_counts.highlight_count,
            notification_count: unread_notification_counts.notification_count,
            cached_user_defined_notification_mode: room
                .cached_user_defined_notification_mode()
                .map(Into::into),
            has_room_call: room.has_active_room_call(),
            active_room_call_participants: room
                .active_room_call_participants()
                .iter()
                .map(|u| u.to_string())
                .collect(),
            active_room_call_consensus_intent: room.active_room_call_consensus_intent().into(),
            is_marked_unread: room.is_marked_unread(),
            num_unread_messages: room.num_unread_messages(),
            num_unread_notifications: room.num_unread_notifications(),
            num_unread_mentions: room.num_unread_mentions(),
            fully_read_event_id: room.fully_read_event_id().map(|id| id.to_string()),
            pinned_event_ids,
            join_rule,
            history_visibility: room.history_visibility_or_default().try_into()?,
            power_levels: power_levels.map(Arc::new),
            room_version: room.version().map(|version| version.to_string()),
            privileged_creators_role: room
                .version()
                .and_then(|version| version.rules())
                .map(|rules| rules.authorization.explicitly_privilege_room_creators)
                .unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use matrix_sdk::test_utils::mocks::MatrixMockServer;
    use matrix_sdk_test::InvitedRoomBuilder;
    use ruma::{events::AnyStrippedStateEvent, room_id, serde::Raw};

    use super::RoomInfo;
    use crate::room::Membership;

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

    /// The sender is named even when they do not resolve to a member.
    ///
    /// This is the ordinary shape of an invitation: the homeserver sends the
    /// recipient's own membership event, and often nothing about the sender
    /// beyond their having been its `sender`.
    #[tokio::test]
    async fn inviter_id_is_present_when_the_member_does_not_resolve() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;

        let sdk_room = server
            .sync_room(
                &client,
                InvitedRoomBuilder::new(room_id!("!invited:localhost")).add_state_event(
                    stripped_member("@bob:localhost", "@example:localhost", "invite"),
                ),
            )
            .await;

        let info = RoomInfo::new(&sdk_room).await.unwrap();

        assert!(matches!(info.membership, Membership::Invited));
        assert_eq!(info.inviter_id.as_deref(), Some("@bob:localhost"));
        assert!(info.inviter.is_none(), "the sender is not in the stripped state");
    }

    /// Both halves are filled, and name the same user, when the sender
    /// resolves.
    #[tokio::test]
    async fn inviter_id_agrees_with_the_member_when_it_resolves() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;

        let sdk_room = server
            .sync_room(
                &client,
                InvitedRoomBuilder::new(room_id!("!invited2:localhost"))
                    .add_state_event(stripped_member(
                        "@bob:localhost",
                        "@example:localhost",
                        "invite",
                    ))
                    .add_state_event(stripped_member("@bob:localhost", "@bob:localhost", "join")),
            )
            .await;

        let info = RoomInfo::new(&sdk_room).await.unwrap();

        assert_eq!(info.inviter_id.as_deref(), Some("@bob:localhost"));
        let inviter = info.inviter.expect("the sender is in the stripped state");
        assert_eq!(inviter.user_id, "@bob:localhost", "the two halves name the same user");
    }

    /// Without the recipient's own membership event there is no sender to name,
    /// and the field is absent even though the room is an invitation.
    ///
    /// The doc on `inviter_id` says exactly this. An earlier version of it
    /// claimed the field was present "whenever the room is an invitation",
    /// which would have invited callers to skip the null branch — and
    /// blocking nobody because a null was assumed impossible is the failure
    /// this change exists to remove.
    #[tokio::test]
    async fn inviter_id_is_absent_without_our_own_membership_event() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;

        let sdk_room = server
            .sync_room(
                &client,
                InvitedRoomBuilder::new(room_id!("!invited3:localhost"))
                    .add_state_event(stripped_member("@bob:localhost", "@bob:localhost", "join")),
            )
            .await;

        let info = RoomInfo::new(&sdk_room).await.unwrap();

        assert!(matches!(info.membership, Membership::Invited), "the room really is an invitation");
        assert!(info.inviter_id.is_none());
        assert!(info.inviter.is_none());
    }

    /// A room that is not an invitation carries neither half.
    #[tokio::test]
    async fn a_joined_room_has_no_inviter() {
        let server = MatrixMockServer::new().await;
        let client = server.client_builder().build().await;
        let sdk_room = server.sync_joined_room(&client, room_id!("!joined:localhost")).await;

        let info = RoomInfo::new(&sdk_room).await.unwrap();

        assert!(matches!(info.membership, Membership::Joined));
        assert!(info.inviter_id.is_none());
        assert!(info.inviter.is_none());
    }
}

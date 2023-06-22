use std::sync::Arc;

use anyhow::Context;
use matrix_sdk::{
    event_handler::EventHandlerHandle,
    notification_settings::{
        NotificationSettings as SdkNotificationSettings,
        RoomNotificationMode as SdkRoomNotificationMode,
    },
    ruma::events::push_rules::PushRulesEvent,
    Client as MatrixClient,
};
use ruma::{
    push::{PredefinedOverrideRuleId, PredefinedUnderrideRuleId, RuleKind},
    RoomId,
};
use tokio::sync::RwLock;

use crate::error::NotificationSettingsError;

#[derive(Clone, uniffi::Enum)]
pub enum RoomNotificationMode {
    AllMessages,
    MentionsAndKeywordsOnly,
    Mute,
}

impl From<SdkRoomNotificationMode> for RoomNotificationMode {
    fn from(value: SdkRoomNotificationMode) -> Self {
        match value {
            SdkRoomNotificationMode::AllMessages => Self::AllMessages,
            SdkRoomNotificationMode::MentionsAndKeywordsOnly => Self::MentionsAndKeywordsOnly,
            SdkRoomNotificationMode::Mute => Self::Mute,
        }
    }
}

pub trait NotificationSettingsDelegate: Sync + Send {
    fn notification_settings_did_change(&self);
}

#[derive(Clone, uniffi::Record)]
pub struct RoomNotificationSettings {
    mode: RoomNotificationMode,
    is_default: bool,
}

impl RoomNotificationSettings {
    fn new(mode: RoomNotificationMode, is_default: bool) -> Self {
        RoomNotificationSettings { mode, is_default }
    }
}

#[derive(Clone, uniffi::Object)]
pub struct NotificationSettings {
    sdk_client: MatrixClient,
    sdk_notification_settings: Arc<RwLock<SdkNotificationSettings>>,
    delegate: Arc<RwLock<Option<Box<dyn NotificationSettingsDelegate>>>>,
    event_handler: EventHandlerHandle,
}

impl NotificationSettings {
    pub(crate) fn new(
        sdk_client: MatrixClient,
        sdk_notification_settings: SdkNotificationSettings,
    ) -> Self {
        let delegate: Arc<RwLock<Option<Box<dyn NotificationSettingsDelegate>>>> =
            Arc::new(RwLock::new(None));

        let sdk_notification_settings = Arc::new(RwLock::new(sdk_notification_settings));
        // Listen for PushRulesEvent
        let delegate_clone = delegate.to_owned();
        let event_handler = sdk_client.add_event_handler(move |_: PushRulesEvent| {
            let delegate = delegate_clone.clone();
            async move {
                if let Some(delegate) = delegate.read().await.as_ref() {
                    delegate.notification_settings_did_change();
                }
            }
        });

        Self { sdk_client, sdk_notification_settings, delegate, event_handler }
    }
}

impl Drop for NotificationSettings {
    fn drop(&mut self) {
        self.sdk_client.remove_event_handler(self.event_handler.clone());
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl NotificationSettings {
    /// Sets a delegate.
    pub async fn set_delegate(&self, delegate: Option<Box<dyn NotificationSettingsDelegate>>) {
        *self.delegate.write().await = delegate;
    }

    /// Gets the notification mode for a room.
    pub async fn get_room_notification_mode(
        &self,
        room_id: String,
    ) -> Result<RoomNotificationSettings, NotificationSettingsError> {
        let notification_settings = self.sdk_notification_settings.read().await;
        let parsed_room_id = RoomId::parse(&room_id)
            .map_err(|_e| NotificationSettingsError::InvalidRoomId(room_id))?;
        // Get the current user defined mode for this room
        if let Some(mode) =
            notification_settings.get_user_defined_room_notification_mode(&parsed_room_id).await
        {
            return Ok(RoomNotificationSettings::new(mode.into(), false));
        }

        // If the user didn't defined a notification mode, return the default one for
        // this room
        let room = self
            .sdk_client
            .get_room(&parsed_room_id)
            .context("Room not found")
            .map_err(|_| NotificationSettingsError::RoomNotFound)?;

        let is_encrypted = room.is_encrypted().await.unwrap_or(false);
        let members_count = room.joined_members_count();

        let mode = notification_settings
            .get_default_room_notification_mode(is_encrypted, members_count)
            .await;
        Ok(RoomNotificationSettings::new(mode.into(), true))
    }

    /// Sets the notification mode for a room.
    pub async fn set_room_notification_mode(
        &self,
        room_id: String,
        mode: RoomNotificationMode,
    ) -> Result<(), NotificationSettingsError> {
        let notification_settings = self.sdk_notification_settings.read().await;
        let mode = match mode {
            RoomNotificationMode::AllMessages => SdkRoomNotificationMode::AllMessages,
            RoomNotificationMode::MentionsAndKeywordsOnly => {
                SdkRoomNotificationMode::MentionsAndKeywordsOnly
            }
            RoomNotificationMode::Mute => SdkRoomNotificationMode::Mute,
        };
        let parsed_room_idom_id = RoomId::parse(&room_id)
            .map_err(|_e| NotificationSettingsError::InvalidRoomId(room_id))?;
        notification_settings.set_room_notification_mode(&parsed_room_idom_id, mode).await?;
        Ok(())
    }

    /// Get the default room notification mode
    ///
    /// # Arguments
    ///
    /// * `is_encrypted` - whether the room is encrypted
    /// * `members_count` - the room's members count
    pub async fn get_default_room_notification_mode(
        &self,
        is_encrypted: bool,
        members_count: u64,
    ) -> RoomNotificationMode {
        let notification_settings = self.sdk_notification_settings.read().await;
        let mode = notification_settings
            .get_default_room_notification_mode(is_encrypted, members_count)
            .await;
        mode.into()
    }

    /// Restores the default notification mode for a room
    pub async fn restore_default_room_notification_mode(
        &self,
        room_id: String,
    ) -> Result<(), NotificationSettingsError> {
        let notification_settings = self.sdk_notification_settings.read().await;
        let parsed_room_idom_id = RoomId::parse(&room_id)
            .map_err(|_e| NotificationSettingsError::InvalidRoomId(room_id))?;
        notification_settings.delete_user_defined_room_rules(&parsed_room_idom_id).await?;
        Ok(())
    }

    /// Get whether some enabled keyword rules exist.
    pub async fn contains_keywords_rules(&self) -> bool {
        let notification_settings = self.sdk_notification_settings.read().await;
        notification_settings.contains_keyword_rules().await
    }

    /// Get whether room mentions are enabled.
    pub async fn is_room_mention_enabled(&self) -> Result<bool, NotificationSettingsError> {
        let notification_settings = self.sdk_notification_settings.read().await;
        let enabled = notification_settings
            .is_push_rule_enabled(
                RuleKind::Override,
                PredefinedOverrideRuleId::IsRoomMention.as_str(),
            )
            .await?;
        Ok(enabled)
    }

    /// Set whether room mentions are enabled.
    pub async fn set_room_mention_enabled(
        &self,
        enabled: bool,
    ) -> Result<(), NotificationSettingsError> {
        let notification_settings = self.sdk_notification_settings.read().await;
        notification_settings
            .set_push_rule_enabled(
                RuleKind::Override,
                PredefinedOverrideRuleId::IsRoomMention.as_str(),
                enabled,
            )
            .await?;
        Ok(())
    }

    /// Get whether user mentions are enabled.
    pub async fn is_user_mention_enabled(&self) -> Result<bool, NotificationSettingsError> {
        let notification_settings = self.sdk_notification_settings.read().await;
        let enabled = notification_settings
            .is_push_rule_enabled(
                RuleKind::Override,
                PredefinedOverrideRuleId::IsUserMention.as_str(),
            )
            .await?;
        Ok(enabled)
    }

    /// Set whether user mentions are enabled.
    pub async fn set_user_mention_enabled(
        &self,
        enabled: bool,
    ) -> Result<(), NotificationSettingsError> {
        let notification_settings = self.sdk_notification_settings.read().await;
        notification_settings
            .set_push_rule_enabled(
                RuleKind::Override,
                PredefinedOverrideRuleId::IsUserMention.as_str(),
                enabled,
            )
            .await?;
        Ok(())
    }

    /// Get whether the `.m.rule.call` push rule is enabled
    pub async fn is_call_enabled(&self) -> Result<bool, NotificationSettingsError> {
        let notification_settings = self.sdk_notification_settings.read().await;
        let enabled = notification_settings
            .is_push_rule_enabled(RuleKind::Underride, PredefinedUnderrideRuleId::Call.as_str())
            .await?;
        Ok(enabled)
    }

    /// Set whether the `.m.rule.call` push rule is enabled
    pub async fn set_call_enabled(
        &self,
        enabled: bool,
    ) -> Result<(), NotificationSettingsError> {
        let notification_settings = self.sdk_notification_settings.read().await;
        notification_settings
            .set_push_rule_enabled(
                RuleKind::Underride,
                PredefinedUnderrideRuleId::Call.as_str(),
                enabled,
            )
            .await?;
        Ok(())
    }

    /// Unmute a room.
    pub async fn unmute_room(
        &self,
        room_id: String,
        is_encrypted: bool,
        members_count: u64,
    ) -> Result<(), NotificationSettingsError> {
        let notification_settings = self.sdk_notification_settings.read().await;
        let parsed_room_idom_id = RoomId::parse(&room_id)
            .map_err(|_e| NotificationSettingsError::InvalidRoomId(room_id))?;
        notification_settings
            .unmute_room(&parsed_room_idom_id, is_encrypted, members_count)
            .await?;
        Ok(())
    }
}

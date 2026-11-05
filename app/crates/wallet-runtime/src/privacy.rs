use crate::security::Secret;
use autopilot_privacy::{config::Config, runtime::PrivacyStatus};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivacyCommand {
    Save {
        config: Config,
        consent: bool,
        pin: Secret,
    },
    Connect,
    Disconnect,
}
#[derive(Serialize)]
pub struct PrivacyReply {
    pub status: PrivacyStatus,
    pub config: Config,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipCommand {
    pub name: String,
}

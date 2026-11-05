//! Isolated mainnet prototype with a pinned owned route. No configurable remote fallback.
use autopilot_privacy::config::{ApprovedNode, Config, Network, Ownership};

pub const OWNED_NODE: &str =
    "http://ea7sus7b6kcykh4dqrcvmqwezmuv3wyurmhkz67kjoyvfh6tpsm7zmid.onion:18089";

pub fn config() -> Config {
    Config {
        network: Network::Mainnet,
        nodes: vec![ApprovedNode {
            id: "17443391700000000000000000000001".into(),
            label: "AutoPilot owned node · Helsinki".into(),
            endpoint: OWNED_NODE.into(),
            ownership: Ownership::Personal,
            approved: true,
            enabled: true,
        }],
        ..Config::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        privacy::PrivacyCommand,
        runner::Runtime,
        security::SecurityCommand,
        send::SendCommand,
        setup::{SetupCommand, WalletSetup},
    };
    use autopilot_wallet_lab::supervisor::Supervisor;
    use serde_json::json;
    fn root() -> std::path::PathBuf {
        std::env::current_dir()
            .unwrap()
            .join(".runtime/mainnet-boundaries")
            .join(uuid::Uuid::new_v4().simple().to_string())
    }

    #[tokio::test]
    async fn network_directories_cannot_be_reused_and_mainnet_cannot_start_local_daemon() {
        let dir = root();
        let mut supervisor = Supervisor::new_mainnet(dir.clone(), dir.clone(), config())
            .await
            .unwrap();
        assert_eq!(supervisor.wallet_name(), "mainnet-wallet");
        assert!(supervisor.start_node().await.is_err());
        assert!(supervisor.daemon.is_none());
        drop(supervisor);
        assert!(Supervisor::new_guarded(dir.clone(), dir.clone())
            .await
            .is_err());
        let saved = std::fs::read(dir.join("privacy/privacy.json")).unwrap();
        let mut altered = config();
        altered.nodes[0].approved = false;
        assert!(Supervisor::new_mainnet(dir.clone(), dir.clone(), altered)
            .await
            .is_err());
        assert_eq!(
            saved,
            std::fs::read(dir.join("privacy/privacy.json")).unwrap()
        );
        let stage = root();
        drop(
            Supervisor::new_guarded(stage.clone(), stage.clone())
                .await
                .unwrap(),
        );
        assert!(Supervisor::new_mainnet(stage.clone(), stage, config())
            .await
            .is_err());
        let legacy = root();
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("existing-wallet"), b"keep").unwrap();
        assert!(
            Supervisor::new_mainnet(legacy.clone(), legacy.clone(), config())
                .await
                .is_err()
        );
        assert_eq!(
            std::fs::read(legacy.join("existing-wallet")).unwrap(),
            b"keep"
        );
    }

    #[tokio::test]
    async fn mainnet_rejects_stagenet_setup_unconnected_payments_and_policy_changes() {
        let dir = root();
        let runtime = Runtime::start_mainnet(dir.clone(), dir.clone())
            .await
            .unwrap();
        let reply = runtime
            .client
            .security_command(
                SecurityCommand::Configure {
                    pin: "083962".into(),
                    confirm_pin: "083962".into(),
                },
                None,
            )
            .await
            .unwrap();
        let permit = runtime
            .client
            .authorize(reply.session.as_deref())
            .await
            .unwrap();
        assert!(runtime
            .client
            .command_authorized(crate::runner::Command::NewAddress, permit)
            .await
            .is_err());
        let wrong = SetupCommand::Create {
            name: "Wrong network".into(),
            network: "stagenet".into(),
        };
        assert!(runtime
            .client
            .setup_authorized(wrong, permit)
            .await
            .is_err());
        for command in [
            SendCommand::Prepare {
                address: "invalid".into(),
                amount: "0.001".into(),
                priority: Default::default(),
            },
            SendCommand::Confirm {
                id: "invalid".into(),
                pin: Some("083962".into()),
            },
            SendCommand::Check,
        ] {
            assert!(runtime
                .client
                .send_authorized(command, permit)
                .await
                .is_err());
        }
        assert!(runtime
            .client
            .privacy_authorized(
                PrivacyCommand::Save {
                    config: config(),
                    consent: true,
                    pin: "083962".into()
                },
                permit
            )
            .await
            .is_err());
        assert!(!dir.join("wallet-catalog.json").exists());
        assert_eq!(std::fs::read_dir(dir.join("payments")).unwrap().count(), 0);
        runtime.stop().await;
        let restarted = Runtime::start_mainnet(dir.clone(), dir).await.unwrap();
        assert!(restarted
            .client
            .authorize(reply.session.as_deref())
            .await
            .is_err());
        restarted.stop().await;
    }

    #[test]
    fn catalog_and_setup_networks_are_immutable() {
        let create = SetupCommand::Create {
            name: "Mainnet".into(),
            network: "mainnet".into(),
        };
        assert!(create.validate().is_err());
        assert!(create.validate_for(Network::Mainnet).is_ok());
        let dir = root();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("wallet-catalog.json"),
            serde_json::to_vec(
                &json!({"schema":1,"network":"stagenet","active":null,"wallets":[]}),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(WalletSetup::load_for(&dir, Network::Mainnet).is_err());
    }
}

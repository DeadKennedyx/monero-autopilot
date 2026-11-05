use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

pub struct AppPaths {
    pub data: PathBuf,
    pub binaries: PathBuf,
}

/// Installed applications never use the launcher's working directory for data
/// or executable discovery. A project path selects development binaries only;
/// both launch modes reuse the proven mainnet profile without migrating keys.
pub fn resolve(
    project: Option<PathBuf>,
    data: Option<PathBuf>,
    executable: &Path,
    local_app_data: Option<&OsStr>,
) -> Result<AppPaths, &'static str> {
    let binaries = match &project {
        Some(root) => {
            if !root.is_absolute() {
                return Err("The project directory must be an absolute path.");
            }
            root.join(".tools/monero/release/monero-x86_64-w64-mingw32-v0.18.5.4")
        }
        None => executable
            .parent()
            .ok_or("Could not resolve the application folder.")?
            .join("monero"),
    };
    let data = match data {
        Some(path) => {
            if !path.is_absolute() {
                return Err("The mainnet data directory must be an absolute path.");
            }
            path
        }
        None => {
            let base =
                PathBuf::from(local_app_data.ok_or("Windows local app data is unavailable.")?);
            if !base.is_absolute() {
                return Err("Windows local app data must be an absolute path.");
            }
            // Keep the existing mainnet directory name: renaming or silently
            // falling back would strand the user's catalog, PIN and history.
            base.join("MoneroAutoPilot/mainnet-prototype")
        }
    };
    Ok(AppPaths { data, binaries })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_paths_separate_binaries_and_wallet_data() {
        let profile = std::env::temp_dir().join("autopilot-path-test/user-profile");
        let program = std::env::temp_dir().join("autopilot-path-test/installed/app.exe");
        let paths = resolve(None, None, &program, Some(profile.as_os_str())).unwrap();
        assert_eq!(paths.binaries, program.parent().unwrap().join("monero"));
        assert_eq!(
            paths.data,
            profile.join("MoneroAutoPilot/mainnet-prototype")
        );
        assert_ne!(paths.data, profile.join("MoneroAutoPilot/stagenet"));
        assert!(!paths.data.starts_with(program.parent().unwrap()));
    }

    #[test]
    fn development_binaries_reuse_the_same_mainnet_profile_as_the_installed_app() {
        let root = std::env::temp_dir().join("autopilot-development");
        let profile = std::env::temp_dir().join("autopilot-path-test/profile");
        let paths = resolve(
            Some(root.clone()),
            None,
            Path::new("irrelevant.exe"),
            Some(profile.as_os_str()),
        )
        .unwrap();
        let installed = resolve(
            None,
            None,
            Path::new("installed/app.exe"),
            Some(profile.as_os_str()),
        )
        .unwrap();
        assert_eq!(paths.data, installed.data);
        assert_ne!(paths.data, root.join(".runtime/wallet-lab"));
        assert_eq!(
            paths.binaries,
            root.join(".tools/monero/release/monero-x86_64-w64-mingw32-v0.18.5.4")
        );
    }

    #[test]
    fn explicit_test_data_does_not_need_the_real_user_profile() {
        let data = std::env::temp_dir().join("autopilot-isolated-test");
        let paths = resolve(
            None,
            Some(data.clone()),
            Path::new("installed/app.exe"),
            None,
        )
        .unwrap();
        assert_eq!(paths.data, data);
    }

    #[test]
    fn missing_profile_cannot_fall_back_to_install_or_working_directory() {
        assert!(resolve(None, None, Path::new("installed/app.exe"), None).is_err());
        assert!(resolve(
            None,
            None,
            Path::new("installed/app.exe"),
            Some(OsStr::new("relative"))
        )
        .is_err());
        assert!(resolve(
            Some(std::env::temp_dir()),
            None,
            Path::new("installed/app.exe"),
            None
        )
        .is_err());
    }

    #[test]
    fn relative_overrides_cannot_select_a_wallet_from_the_working_directory() {
        assert!(resolve(
            None,
            Some("relative-wallet".into()),
            Path::new("installed/app.exe"),
            None
        )
        .is_err());
        assert!(resolve(
            Some("relative-project".into()),
            Some(std::env::temp_dir()),
            Path::new("installed/app.exe"),
            None
        )
        .is_err());
    }
}

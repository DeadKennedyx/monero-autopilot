//! Local application lock and per-payment PIN verification. No PIN is persisted.
//! The Windows account remains the trust boundary for wallet files and processes.
use argon2::{Algorithm, Argon2, Params, Version};
use autopilot_wallet_lab::{platform, LabResult};
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, Notify, OwnedMutexGuard};
use zeroize::{Zeroize, Zeroizing};

pub const IDLE_SECONDS: u64 = 300;
pub const LOCKED: &str = "Wallet locked. Enter your PIN to continue.";
#[derive(Clone, Default)]
pub struct Secret(Zeroizing<String>);
impl Secret {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self(Zeroizing::new(s.into()))
    }
}
impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(|s| Self(Zeroizing::new(s)))
    }
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecurityCommand {
    Configure {
        pin: Secret,
        confirm_pin: Secret,
    },
    Unlock {
        pin: Secret,
    },
    Lock,
    Activity,
    ChangePin {
        current_pin: Secret,
        new_pin: Secret,
        confirm_pin: Secret,
    },
}
#[derive(Clone, Serialize)]
pub struct SecuritySnapshot {
    pub configured: bool,
    pub locked: bool,
    pub idle_seconds: u64,
    pub idle_remaining_seconds: u64,
    pub retry_after_seconds: u64,
    pub error: Option<String>,
}
#[derive(Serialize)]
pub struct SecurityReply {
    pub security: SecuritySnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}
impl Drop for SecurityReply {
    fn drop(&mut self) {
        if let Some(s) = &mut self.session {
            s.zeroize();
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u8,
    salt: [u8; 16],
    hash: [u8; 32],
    failures: u32,
    blocked_until: u64,
    last_attempt: u64,
}
impl Drop for Record {
    fn drop(&mut self) {
        self.hash.zeroize();
    }
}
struct Access {
    root: PathBuf,
    record: Option<Record>,
    fault: Option<&'static str>,
    configured: bool,
    session: Option<Zeroizing<String>>,
    epoch: u64,
    last_activity: Instant,
}
#[derive(Clone)]
pub struct Security {
    inner: Arc<Mutex<Access>>,
    pub changed: Arc<Notify>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn valid_pin(pin: &str) -> bool {
    (4..=6).contains(&pin.len()) && pin.bytes().all(|c| c.is_ascii_digit())
}
fn backoff(failures: u32) -> u64 {
    match failures {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4 => 8,
        5 => 30,
        6 => 60,
        7 => 120,
        8 => 300,
        _ => 900,
    }
}
async fn hash(pin: Secret, salt: [u8; 16]) -> LabResult<Zeroizing<[u8; 32]>> {
    tokio::task::spawn_blocking(move || {
        let params = Params::new(19456, 2, 1, Some(32))
            .map_err(|_| "PIN hashing configuration is unavailable.")?;
        let mut output = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(pin.as_str().as_bytes(), &salt, output.as_mut())
            .map_err(|_| "PIN hashing failed.")?;
        Ok(output)
    })
    .await
    .map_err(|_| "PIN verification was interrupted.")?
}
impl Access {
    fn revoke(&mut self) {
        self.session = None;
        self.epoch = self.epoch.wrapping_add(1);
    }
    fn expire(&mut self) {
        if self.session.is_some()
            && self.last_activity.elapsed() >= Duration::from_secs(IDLE_SECONDS)
        {
            self.revoke();
        }
    }
    fn valid_epoch(&mut self, epoch: Option<u64>) -> LabResult<()> {
        self.expire();
        if self.fault.is_some() || self.session.is_none() || epoch != Some(self.epoch) {
            return Err(LOCKED);
        }
        Ok(())
    }
    fn matches(&mut self, session: Option<&str>) -> bool {
        self.expire();
        self.fault.is_none()
            && self
                .session
                .as_ref()
                .zip(session)
                .is_some_and(|(a, b)| bool::from(a.as_bytes().ct_eq(b.as_bytes())))
    }
    fn remaining_delay(&self) -> u64 {
        self.record
            .as_ref()
            .map_or(0, |r| r.blocked_until.saturating_sub(now()))
    }
    fn status(&mut self, session: Option<&str>) -> SecuritySnapshot {
        let unlocked = self.matches(session);
        SecuritySnapshot {
            configured: self.configured,
            locked: !unlocked,
            idle_seconds: IDLE_SECONDS,
            idle_remaining_seconds: if unlocked {
                IDLE_SECONDS.saturating_sub(self.last_activity.elapsed().as_secs())
            } else {
                0
            },
            retry_after_seconds: self.remaining_delay(),
            error: self.fault.map(str::to_string),
        }
    }
    fn persist(&mut self, record: Record) -> LabResult<()> {
        let result = (|| {
            let plain = Zeroizing::new(
                serde_json::to_vec(&record).map_err(|_| "Could not encode PIN protection.")?,
            );
            let sealed = platform::protect(&plain)?;
            let temporary = self
                .root
                .join(format!("pin-{}.tmp", uuid::Uuid::new_v4().simple()));
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|_| "Could not save PIN protection.")?;
            file.write_all(&sealed)
                .and_then(|_| file.sync_all())
                .map_err(|_| "Could not flush PIN protection.")?;
            drop(file);
            std::fs::rename(&temporary, self.root.join("pin.dpapi"))
                .map_err(|_| "Could not commit PIN protection.")
        })();
        if result.is_err() {
            self.fault = Some("PIN protection could not be saved. Wallet access is blocked.");
            self.revoke();
        }
        result?;
        self.record = Some(record);
        Ok(())
    }
    async fn verify(&mut self, pin: &Secret) -> LabResult<()> {
        if let Some(error) = self.fault {
            return Err(error);
        }
        if !valid_pin(pin.as_str()) {
            return Err("Enter a PIN containing 4 to 6 digits.");
        }
        if self.remaining_delay() > 0 {
            return Err("Too many PIN attempts. Wait for the countdown before trying again.");
        }
        let mut attempt = self.record.clone().ok_or("Set up your PIN first.")?;
        // Count and flush BEFORE hashing. A crash cannot erase an attempted guess.
        attempt.failures = attempt.failures.saturating_add(1);
        attempt.last_attempt = now();
        attempt.blocked_until = now().saturating_add(backoff(attempt.failures));
        let salt = attempt.salt;
        let expected = Zeroizing::new(attempt.hash);
        self.persist(attempt)?;
        let actual = hash(pin.clone(), salt).await?;
        if !bool::from(actual.as_ref().ct_eq(expected.as_ref())) {
            return Err("Incorrect PIN.");
        }
        let mut success = self
            .record
            .clone()
            .ok_or("PIN protection is unavailable.")?;
        success.failures = 0;
        success.blocked_until = 0;
        self.persist(success)?;
        Ok(())
    }
    fn new_session(&mut self) -> String {
        self.revoke();
        self.last_activity = Instant::now();
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        self.session = Some(Zeroizing::new(token.clone()));
        token
    }
}
impl Security {
    pub async fn open(root: PathBuf) -> LabResult<Self> {
        platform::private_directory(&root).await?;
        let marker = root.join("configured");
        let path = root.join("pin.dpapi");
        let configured = marker.exists() || path.exists();
        let record = if configured {
            (|| {
                if !marker.is_file() {
                    return Err("PIN setup is incomplete. Existing wallet files are preserved.");
                }
                let bytes = std::fs::read(&path).map_err(|_| {
                    "PIN protection is missing. Existing wallet files are preserved."
                })?;
                if bytes.len() > 4096 {
                    return Err("PIN protection is damaged.");
                }
                let plain = platform::unprotect(&bytes)?;
                let r: Record =
                    serde_json::from_slice(&plain).map_err(|_| "PIN protection is damaged.")?;
                if r.schema != 1 || r.blocked_until > r.last_attempt.saturating_add(900) {
                    return Err("PIN protection is damaged.");
                }
                Ok(Some(r))
            })()
        } else {
            Ok(None)
        };
        let (record, fault) = match record {
            Ok(r) => (r, None),
            Err(e) => (None, Some(e)),
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(Access {
                root,
                record,
                fault,
                configured,
                session: None,
                epoch: 0,
                last_activity: Instant::now(),
            })),
            changed: Arc::new(Notify::new()),
        })
    }
    pub async fn snapshot(&self, session: Option<&str>) -> SecuritySnapshot {
        self.inner.lock().await.status(session)
    }
    pub async fn permit(&self, session: Option<&str>) -> LabResult<u64> {
        let mut access = self.inner.lock().await;
        if !access.matches(session) {
            return Err(LOCKED);
        }
        Ok(access.epoch)
    }
    pub async fn check(&self, epoch: Option<u64>) -> LabResult<()> {
        self.inner.lock().await.valid_epoch(epoch)
    }
    pub async fn locked(&self) -> bool {
        let mut a = self.inner.lock().await;
        a.expire();
        a.session.is_none() || a.fault.is_some()
    }
    pub async fn lock(&self) {
        self.inner.lock().await.revoke();
        self.changed.notify_one();
    }
    pub async fn execute(
        &self,
        command: SecurityCommand,
        session: Option<&str>,
    ) -> LabResult<SecurityReply> {
        let wake = !matches!(&command, SecurityCommand::Activity);
        let mut a = self.inner.lock().await;
        let mut issued = None;
        match command {
            SecurityCommand::Configure { pin, confirm_pin } => {
                if a.configured || a.fault.is_some() {
                    return Err("A PIN is already configured or needs attention.");
                }
                if !valid_pin(pin.as_str()) {
                    return Err(
                        "Choose a PIN containing 4 to 6 digits. Six digits are recommended.",
                    );
                }
                if !bool::from(
                    pin.as_str()
                        .as_bytes()
                        .ct_eq(confirm_pin.as_str().as_bytes()),
                ) {
                    return Err("The PIN entries do not match.");
                }
                let salt = *uuid::Uuid::new_v4().as_bytes();
                let digest = hash(pin, salt).await?;
                let mut marker = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(a.root.join("configured"))
                    .map_err(|_| "Could not record PIN setup.")?;
                marker
                    .write_all(b"PIN required; do not remove")
                    .and_then(|_| marker.sync_all())
                    .map_err(|_| "Could not flush PIN setup.")?;
                a.configured = true;
                a.persist(Record {
                    schema: 1,
                    salt,
                    hash: *digest,
                    failures: 0,
                    blocked_until: 0,
                    last_attempt: 0,
                })?;
                issued = Some(a.new_session());
            }
            SecurityCommand::Unlock { pin } => {
                a.verify(&pin).await?;
                issued = Some(a.new_session());
            }
            SecurityCommand::Lock => {
                a.revoke();
            }
            SecurityCommand::Activity => {
                if !a.matches(session) {
                    return Err(LOCKED);
                }
                a.last_activity = Instant::now();
            }
            SecurityCommand::ChangePin {
                current_pin,
                new_pin,
                confirm_pin,
            } => {
                if !a.matches(session) {
                    return Err(LOCKED);
                }
                if !valid_pin(new_pin.as_str()) {
                    return Err("Choose a PIN containing 4 to 6 digits.");
                }
                if !bool::from(
                    new_pin
                        .as_str()
                        .as_bytes()
                        .ct_eq(confirm_pin.as_str().as_bytes()),
                ) {
                    return Err("The PIN entries do not match.");
                }
                a.verify(&current_pin).await?;
                let salt = *uuid::Uuid::new_v4().as_bytes();
                let digest = hash(new_pin, salt).await?;
                a.persist(Record {
                    schema: 1,
                    salt,
                    hash: *digest,
                    failures: 0,
                    blocked_until: 0,
                    last_attempt: 0,
                })?;
                a.revoke();
            }
        }
        let status = a.status(issued.as_deref().or(session));
        drop(a);
        if wake {
            self.changed.notify_one();
        }
        Ok(SecurityReply {
            security: status,
            session: issued,
        })
    }
    pub async fn verify_sensitive(
        &self,
        epoch: Option<u64>,
        pin: Option<&Secret>,
    ) -> LabResult<()> {
        let mut a = self.inner.lock().await;
        a.valid_epoch(epoch)?;
        a.verify(pin.ok_or("Enter your PIN to authorize this action.")?)
            .await?;
        a.valid_epoch(epoch)
    }
    pub async fn authorize_payment(
        &self,
        epoch: Option<u64>,
        pin: Option<&Secret>,
        wallet: &str,
        id: &str,
    ) -> LabResult<PaymentAuthorization> {
        let mut access = self.inner.clone().lock_owned().await;
        access.valid_epoch(epoch)?;
        access
            .verify(pin.ok_or("Enter your PIN to authorize this payment.")?)
            .await?;
        access.valid_epoch(epoch)?;
        Ok(PaymentAuthorization {
            access,
            epoch,
            wallet: wallet.into(),
            id: id.into(),
        })
    }
}
/// One-use authorization held only across the synchronous durable attempt marker.
/// Lock can revoke later operations while an already-authorized relay completes.
pub struct PaymentAuthorization {
    access: OwnedMutexGuard<Access>,
    epoch: Option<u64>,
    wallet: String,
    id: String,
}
impl PaymentAuthorization {
    pub(crate) fn check(&mut self, wallet: &str, id: &str) -> LabResult<()> {
        self.access.valid_epoch(self.epoch)?;
        if self.wallet != wallet || self.id != id {
            return Err("Payment authorization does not match this preview.");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn store() -> Security {
        Security::open(
            std::env::current_dir()
                .unwrap()
                .join(".runtime/security-tests")
                .join(uuid::Uuid::new_v4().simple().to_string()),
        )
        .await
        .unwrap()
    }
    async fn configure(s: &Security) -> String {
        s.execute(
            SecurityCommand::Configure {
                pin: "824619".into(),
                confirm_pin: "824619".into(),
            },
            None,
        )
        .await
        .unwrap()
        .session
        .clone()
        .unwrap()
    }
    #[test]
    fn pin_format_and_backoff_are_bounded() {
        for p in ["123", "1234567", "１２３４", "12 4", "123a", ""] {
            assert!(!valid_pin(p));
        }
        for p in ["0123", "12345", "123456"] {
            assert!(valid_pin(p));
        }
        assert_eq!(backoff(5), 30);
        assert_eq!(backoff(u32::MAX), 900);
        assert_eq!(IDLE_SECONDS, 300);
    }
    #[tokio::test]
    async fn session_idle_lock_restart_and_redaction() {
        let s = store().await;
        let session = configure(&s).await;
        let epoch = s.permit(Some(&session)).await.unwrap();
        assert!(s.snapshot(None).await.locked);
        assert!(!s.snapshot(Some(&session)).await.locked);
        let text = serde_json::to_string(&s.snapshot(Some(&session)).await).unwrap();
        assert!(!text.contains("824619") && !text.contains(&session));
        {
            s.inner.lock().await.last_activity = Instant::now() - Duration::from_secs(301);
        }
        assert!(s.check(Some(epoch)).await.is_err());
        assert!(s.locked().await);
        let root = s.inner.lock().await.root.clone();
        let reopened = Security::open(root).await.unwrap();
        assert!(reopened.locked().await);
        assert!(reopened.snapshot(None).await.configured);
    }
    #[tokio::test]
    async fn failures_survive_restart_and_pin_change_revokes_old_sessions() {
        let s = store().await;
        let session = configure(&s).await;
        assert!(s
            .execute(
                SecurityCommand::Unlock {
                    pin: "999999".into()
                },
                None
            )
            .await
            .is_err());
        let root = s.inner.lock().await.root.clone();
        let reopened = Security::open(root).await.unwrap();
        assert_eq!(
            reopened
                .inner
                .lock()
                .await
                .record
                .as_ref()
                .unwrap()
                .failures,
            1
        );
        {
            let mut a = s.inner.lock().await;
            a.record.as_mut().unwrap().blocked_until = 0;
        }
        assert!(s
            .execute(
                SecurityCommand::ChangePin {
                    current_pin: "824619".into(),
                    new_pin: "2947".into(),
                    confirm_pin: "2947".into()
                },
                Some(&session)
            )
            .await
            .is_ok());
        assert!(s.permit(Some(&session)).await.is_err());
        assert!(s
            .execute(SecurityCommand::Unlock { pin: "2947".into() }, None)
            .await
            .is_ok());
    }
    #[tokio::test]
    async fn missing_corrupt_protection_cannot_reset_pin() {
        let s = store().await;
        configure(&s).await;
        let root = s.inner.lock().await.root.clone();
        std::fs::write(root.join("pin.dpapi"), b"damaged").unwrap();
        let damaged = Security::open(root.clone()).await.unwrap();
        assert!(damaged.snapshot(None).await.error.is_some());
        assert!(damaged
            .execute(
                SecurityCommand::Configure {
                    pin: "1234".into(),
                    confirm_pin: "1234".into()
                },
                None
            )
            .await
            .is_err());
        std::fs::remove_file(root.join("pin.dpapi")).unwrap();
        let missing = Security::open(root).await.unwrap();
        assert!(missing.snapshot(None).await.error.is_some());
        assert!(missing.locked().await);
    }
    #[tokio::test]
    async fn payment_authorization_is_pin_checked_and_bound_to_exact_preview() {
        let s = store().await;
        let session = configure(&s).await;
        let epoch = Some(s.permit(Some(&session)).await.unwrap());
        assert!(s
            .authorize_payment(epoch, None, "wallet", "payment-a")
            .await
            .is_err());
        let mut permit = s
            .authorize_payment(epoch, Some(&Secret::from("824619")), "wallet", "payment-a")
            .await
            .unwrap();
        assert!(permit.check("other-wallet", "payment-a").is_err());
        assert!(permit.check("wallet", "payment-b").is_err());
        assert!(permit.check("wallet", "payment-a").is_ok());
        drop(permit);
        s.lock().await;
        assert!(s
            .authorize_payment(epoch, Some(&Secret::from("824619")), "wallet", "payment-a")
            .await
            .is_err());
    }
}

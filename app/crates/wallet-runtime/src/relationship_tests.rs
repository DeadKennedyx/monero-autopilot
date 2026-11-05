use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Mutex,
};
#[derive(Default)]
struct Wallet {
    addresses: Mutex<Vec<WalletAddress>>,
    creates: AtomicUsize,
    lose_response: AtomicBool,
    fail_save: AtomicBool,
}
impl SubaddressWallet for Wallet {
    async fn addresses(&self) -> LabResult<Vec<WalletAddress>> {
        Ok(self.addresses.lock().unwrap().clone())
    }
    async fn create(&self, label: &str) -> LabResult<WalletAddress> {
        let index = self.creates.fetch_add(1, Ordering::SeqCst) as u32 + 1;
        let address = WalletAddress {
            index,
            address: format!(
                "7{}{}",
                "a".repeat(92),
                if index == 1 { "AA" } else { "BB" }
            ),
            label: label.into(),
        };
        self.addresses.lock().unwrap().push(address.clone());
        if self.lose_response.swap(false, Ordering::SeqCst) {
            return Err("Simulated lost create response.");
        }
        Ok(address)
    }
    async fn validate(&self, address: &str) -> LabResult<()> {
        if address_shape(address) {
            Ok(())
        } else {
            Err("Invalid fixture")
        }
    }
    async fn save(&self) -> LabResult<()> {
        if self.fail_save.load(Ordering::SeqCst) {
            Err("Simulated save failure.")
        } else {
            Ok(())
        }
    }
}
async fn folder() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "autopilot-relationships-test-{}",
        uuid::Uuid::new_v4().simple()
    ));
    platform::private_directory(&root).await.unwrap();
    root
}
fn cleanup(root: &Path) {
    let path = fs::canonicalize(root).unwrap();
    let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
    assert_eq!(path.parent(), Some(parent.as_path()));
    assert!(path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("autopilot-relationships-test-"));
    fs::remove_dir_all(path).unwrap();
}
#[tokio::test]
async fn distinct_relationships_are_idempotent_private_and_wallet_bound() {
    let root = folder().await;
    let wallet = Wallet::default();
    let identity = "a".repeat(64);
    let mut book = RelationshipBook::open(root.clone(), &identity).unwrap();
    let first = book.assign(&wallet, "Customer Alpha").await.unwrap();
    let again = book.assign(&wallet, " customer alpha ").await.unwrap();
    assert_eq!(first.id, again.id);
    assert_eq!(first.address, again.address);
    let second = book.assign(&wallet, "Customer Beta").await.unwrap();
    assert_ne!(first.address, second.address);
    assert_eq!(wallet.creates.load(Ordering::SeqCst), 2);
    let bytes = fs::read(root.join("relationships.dpapi")).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("Customer"));
    assert!(wallet
        .addresses
        .lock()
        .unwrap()
        .iter()
        .all(|a| !a.label.contains("Customer")));
    assert!(RelationshipBook::open(root.clone(), &"b".repeat(64)).is_err());
    let reopened = RelationshipBook::open(root.clone(), &identity).unwrap();
    assert_eq!(reopened.completed().len(), 2);
    cleanup(&root);
}
#[tokio::test]
async fn interrupted_creation_and_save_reconcile_without_duplicate_addresses() {
    let root = folder().await;
    let wallet = Wallet::default();
    let identity = "a".repeat(64);
    let mut book = RelationshipBook::open(root.clone(), &identity).unwrap();
    wallet.lose_response.store(true, Ordering::SeqCst);
    assert!(book.assign(&wallet, "Customer Alpha").await.is_err());
    assert!(book.completed().is_empty());
    drop(book);
    let mut book = RelationshipBook::open(root.clone(), &identity).unwrap();
    wallet.fail_save.store(true, Ordering::SeqCst);
    assert!(book.assign(&wallet, "Customer Alpha").await.is_err());
    assert!(book.completed().is_empty());
    wallet.fail_save.store(false, Ordering::SeqCst);
    let first = book.assign(&wallet, "Customer Alpha").await.unwrap();
    assert_eq!(first.address_index, Some(1));
    assert_eq!(wallet.creates.load(Ordering::SeqCst), 1);
    wallet.addresses.lock().unwrap().clear();
    assert!(book.assign(&wallet, "Customer Alpha").await.is_err());
    assert_eq!(
        wallet.creates.load(Ordering::SeqCst),
        1,
        "An assigned address cannot be silently replaced after a restore"
    );
    fs::write(root.join("relationships.dpapi"), b"damaged").unwrap();
    assert!(RelationshipBook::open(root.clone(), &identity).is_err());
    cleanup(&root);
}

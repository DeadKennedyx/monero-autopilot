pub mod api;
pub mod platform;
pub mod rpc;
pub mod runner;
pub mod supervisor;
pub mod tor;

pub const VERSION: &str = "0.18.5.4";
// Extracted from the archive after verifying binaryFate's signed manifest.
pub const DAEMON_SHA256: &str = "08a63d368e6443ac4359434d3d816f2b9663fa457c7e2bc158684e4d34e8f2a5";
pub const WALLET_SHA256: &str = "11112433f043b0cad8093d2e2abbd15bbe1914b40929f41d1f90798e7d436239";
pub const WALLET_NAME: &str = "disposable-stagenet";
pub type LabResult<T> = Result<T, &'static str>;

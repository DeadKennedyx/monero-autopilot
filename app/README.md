# Desktop wallet

The current native build targets Windows x64 using Tauri 2, React and Rust. Shared wallet libraries are maintained under `crates/`; their existing internal Cargo package names are retained for compatibility.

## Prerequisites

- Node.js 24 or newer and pnpm 11.25.0.
- Rust with the Windows MSVC toolchain.
- Visual Studio Build Tools with Desktop development with C++ and a Windows SDK.
- Microsoft Edge WebView2 Runtime. The installer can bootstrap it.

Run the following commands from this `app` directory in PowerShell:

```powershell
pnpm install --frozen-lockfile
./scripts/setup-monero.ps1
./scripts/setup-tor.ps1
./scripts/build-app.ps1
./scripts/start-app.ps1
```

The setup scripts download official Monero and Tor releases, verify their signatures and pinned checksums, and prepare ignored `.tools/` files. Tor is embedded during compilation. The development launcher supplies the prepared Monero executable to the app.

`start-app.ps1` uses the existing `%LOCALAPPDATA%\MoneroAutoPilot\mainnet-prototype` profile directory. Its historical name is intentional so existing wallets keep working. To use a separate profile, pass `-DataDirectory` with an absolute path. Do not run two app instances against the same profile.

## Checks

```powershell
pnpm build:app
pnpm test
cargo test --manifest-path src-tauri/Cargo.toml --locked
cargo test --manifest-path crates/wallet-runtime/Cargo.toml --lib
cargo test --manifest-path crates/wallet-rpc/Cargo.toml --lib
cargo test --manifest-path crates/autopilot-privacy/Cargo.toml --lib
cargo test --manifest-path crates/monero-autopilot-core/Cargo.toml --lib
```

Frontend tests use synthetic fixtures and write reports to `.runtime/tests/`. They use Edge on Windows by default; `PLAYWRIGHT_CHANNEL` can select another installed Playwright browser channel. Native tests require the verified Tor files prepared above. These automated checks do not establish that a real transfer has completed.

## Installer

After preparing dependencies and runtimes:

```powershell
./scripts/build-installer.ps1
```

The NSIS output is under `src-tauri/target/release/bundle/nsis/`. The build verifies the packaged runtime files and includes their licenses. Signing, release publication and enabling the website's download link are separate release steps.

Generated frontend bundles, installers, runtime binaries, wallet data and test reports are excluded from Git.

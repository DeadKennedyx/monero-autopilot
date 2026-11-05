# Monero AutoPilot — Windows app and component prototypes

## Integrated mainnet app: AutoPilot 0.9.0

Run **START-AUTOPILOT.cmd** for the native Windows wallet. The proven mainnet prototype now supplies the desktop app's Overview, Receive, Send, Activity, Wallets, Connection, and Settings. Built-in Tor connects to the owned mainnet node. A saved wallet opens automatically after unlocking, with clear startup progress and balances that distinguish confirmed funds from funds available to send.

Your existing mainnet profile is reused in place at `%LOCALAPPDATA%\MoneroAutoPilot\mainnet-prototype`, including the PIN, wallet, and protected transaction journal. Close the mainnet prototype before opening the app. The original stagenet profiles remain separate. The app locks on restart and after five idle minutes; every send requires review and PIN authorization. Current limits are 0.01 XMR per payment and a maximum fee of 0.0001 XMR.

Instructions: [Desktop app](apps/desktop/README.md). Integration evidence: [Desktop mainnet validation](docs/desktop-mainnet/README.md). Payment design and prior live test: [Mainnet payments](docs/mainnet-payments/README.md). This local build does not replace the public installer or publish a download.

## Component prototypes

**START-MAINNET-LAB.cmd** retains the standalone mainnet environment for component review. It shares the desktop app's tested UI and existing mainnet profile, so run only one host at a time. See [mainnet prototype instructions](prototypes/mainnet-lab/README.md). The sections below describe earlier prototypes and their historical validation; they are not the current desktop network configuration.

## Prototype 04E

**Wallet lock and payment authorization:** the standalone security prototype was tested before integration. Use the header **Lock** button or **Settings → Wallet lock & payments** to lock or change the PIN. Locking hides wallet data and closes wallet RPC while the local node may keep syncing. The standalone lab uses separate disposable PIN storage and refuses a main-app PIN-configured wallet root. [Design and limits](prototypes/security-lab/README.md); [validation](docs/security-lab/VALIDATION.md). No new software installation is required.

## Prototype 04D

**Wallet setup, backup, and restore:** run `START-SETUP-LAB.cmd` for the standalone prototype, or use **Wallets → Wallets & backup** in the main app. It creates separately stored test wallets, checks a written 25-word recovery phrase, and restores into a fresh wallet using the existing local node. A restored controlled recipient recovered its exact address and 0.001 sXMR and retained them after restart. [Review the flow and limits](prototypes/setup-lab/README.md); [validation evidence](docs/setup-lab/VALIDATION.md). No additional software is needed on this computer.

## Prototype 04A

**Receive and balance:** run `START-RECEIVE-LAB.cmd`, then Open wallet. The separate dashboard generates official stagenet receiving subaddresses and local QR codes, distinguishes pending/confirmed/locked/spendable funds, and preserves the saved wallet through local recovery. It shares the existing blockchain and wallet with 03A/03B; run only one lab at a time.

Source and instructions: [Prototype 04A](prototypes/receive-lab/README.md). Evidence: [receive validation](docs/receive-lab/VALIDATION.md). Wallet features are being proven locally before deploying our primary/fallback cloud nodes. Sending is a later prototype.

## Prototype 03B

**Real local automatic recovery:** run `START-RECOVERY-LAB.cmd`, then Start recovery. Deliberately stop the owned node, observe bounded retries, and verify that the same saved stagenet wallet reopens. The recovery lab also handles an exited wallet backend, saves periodic wallet checkpoints, respects manual stop, and confirms shutdown completion. It reuses the synchronized 03A data; run only one of these labs at a time.

Source and instructions: [Prototype 03B](prototypes/recovery-lab/README.md). Evidence: [recovery validation](docs/recovery-lab/VALIDATION.md). Switching to a second node remains a separate slice after the local wallet workflows.

## Prototype 03A

**Real stagenet wallet backend:** run `START-WALLET-LAB.cmd`. This separate native host supervises official Monero wallet RPC and a pruned local stagenet daemon, protects the test wallet password with Windows DPAPI, and displays actual synchronization. Save/stop/reopen preserves the disposable wallet. Full node and wallet synchronization was confirmed on November 3, 2026.

Source and instructions: [Prototype 03A](prototypes/wallet-lab/README.md). Evidence: [wallet lab validation](docs/wallet-lab/VALIDATION.md). This is a test wallet with no real-money funds; automatic real-wallet failover is a later slice.

## Prototype 02

**Real HTTP recovery lab:** run `START-NETWORK-LAB.cmd` to open the native Rust runner and React dashboard. Stop actual local test servers, inject slow or malformed responses, and inspect privacy filtering, cancellation, measured response times, and server-side request counts. The wallet remains a mock; all addresses are loopback fixtures.

Source and review instructions: [Prototype 02](prototypes/network-lab/README.md). Validation: [network lab checks](docs/network-lab/VALIDATION.md). This native prototype has its own Cargo workspace and lockfile so the original portable WASM demonstration remains independently runnable.

## Prototype 01

A working Rust recovery engine connected to mock node and wallet adapters, with a React + TypeScript review dashboard. This milestone is intentionally separate from the main desktop wallet.

## Review it now

Open **[REVIEW.html](REVIEW.html)** in Edge, Chrome, or Firefox. Everything is embedded; no installation, server, account, or internet connection is needed to run it.

1. Leave the simulation running in **Easy** mode.
2. Click **Simulate Node A failure**.
3. Watch AutoPilot confirm the failure, evaluate permitted alternatives, connect Node B, and resume scanning.
4. Switch to **Private** and fail the personal node. Public node probe counts must remain zero.
5. Use **Pause** and **Step** to inspect individual decisions. **Reset** starts over.

The dashboard includes a quick guide and a manual review checklist. A checkbox records your own review; it is not an automated test result.

**Scope:** all nodes, latency values, chain heights, wallet progress, and failures are fixtures. The Rust decisions actually execute. There is no real wallet, real Tor connection, node discovery, cryptocurrency, balance, seed, or transaction. State lives in memory and resets on reload. The Tauri shell is deferred until after this prototype review.

## What's implemented

- A reusable `monero-autopilot-core` crate with typed node and wallet adapter boundaries.
- Two failed health checks before failover; a single timeout recovers without switching.
- Privacy filtering **before** probing and again before attachment.
- Stagenet and reference-height validation against a fixed, separate test fixture.
- Candidate ranking by observed failure rate, then latency.
- Three recovery rounds with two- and four-tick backoff; no automatic retries after exhaustion.
- Stall detection after four ticks without scan progress; persistent stalls cannot reconnect indefinitely.
- Mock backend exit handling with explicit simulated restart.
- A bounded diagnostic history, pause/step controls, and failure injection.
- A self-contained HTML build running the compiled Rust engine through WebAssembly, not a JavaScript copy of its policy.

## Source layout

```text
crates/monero-autopilot-core/  Wallet-independent decisions, policies, adapter traits
crates/prototype-sim/         Mock adapters, scenario driver, Rust integration tests, WASM ABI
apps/prototype/src/           React dashboard, typed bridge, generated WASM asset
scripts/                     Build, embedding, offline packaging, WASI test runner
tests/                       Compiled WASM contract tests and browser workflow checks
docs/                        Architecture, backend research, security assumptions, roadmap
REVIEW.html                  Ready-to-open review build
```

## Development setup

The included `REVIEW.html` does not need these tools. Rebuilding Prototype 1 requires Node 24+, pnpm 11.25.0, and Rust with the two WebAssembly targets. This build was verified using Rust 1.99.1 and Node 24.22.1 on Windows. Exact frontend versions are recorded in `pnpm-lock.yaml`; Prototype 1's Cargo workspace has no external crate dependencies. Prototype 2's native dependencies are isolated under `prototypes/network-lab`.

```powershell
rustup target add wasm32-unknown-unknown wasm32-wasip1
rustup component add rustfmt clippy
pnpm install --frozen-lockfile
pnpm build:wasm
pnpm build
```

`pnpm dev` starts an optional local Vite development server. The generated `engine.wasm.ts` is included so frontend-only edits do not require Rust. Whenever Rust changes, run `pnpm build:wasm` before `pnpm build`.

The working project is at `%USERPROFILE%\Documents\monero-autopilot-prototype`. Its portable Rust toolchain is stored inside `.tools/rust`, without changing the machine PATH. From the project directory, run `. ./scripts/workspace-env.ps1` to use it in a PowerShell session. The helper resolves paths relative to the project, so moving the entire folder preserves this setup. The toolchain and Visual Studio cache are ignored by Git and excluded from the source archive. On another machine, use your normal Rust installation instead.

## Verification

```powershell
pnpm test:rust
pnpm test:bridge
pnpm test:ui
cargo clippy --workspace --all-targets --target wasm32-wasip1 -- -D warnings
cargo fmt --all --check
```

The Rust runner compiles the actual library tests to WASI and executes them with Node; it avoids requiring Microsoft's native linker. With the installed Visual Studio C++ tools, `cargo test --workspace --lib` also runs the same Rust tests as native Windows executables. Both execution paths passed after moving the project to Documents.

The browser checks use headless installed Edge by default. Set `PLAYWRIGHT_CHANNEL=chrome` to use installed Chrome. They open the exact delivered `REVIEW.html` via `file://`, exercise the controls, check for external requests and script errors, and save screenshots.

**Retested from Documents on November 2, 2026:** the same 17 Rust tests passed on both native Windows and WASI, plus 5 compiled WebAssembly checks and 9 browser checks. TypeScript checking, the production build, Clippy with warnings denied for both Rust targets, and formatting checks passed. See [validation details](docs/VALIDATION.md).

## Next review gate

Review the behavior and interface before promoting anything to the main app. The next proposed prototype is a real network health adapter against controlled local RPC fixtures, followed by official Monero wallet RPC on stagenet. See the [roadmap](docs/ROADMAP.md), [architecture](docs/ARCHITECTURE.md), [backend comparison](docs/BACKENDS.md), and [security assumptions](docs/SECURITY.md).

# Monero AutoPilot

Monero mainnet desktop wallet built with Tauri 2, React, TypeScript, and Rust. The current packaged build targets Windows x64. Wallet operations use a local `monero-wallet-rpc` process; node connections use bundled Tor.

[Windows download](https://moneroautopilot.com/downloads.html) · [Build instructions](app/README.md) · [Contributions](#contributions-welcome) · [Node donations](#node-donations)

The wallet disconnects if the approved node or the tor connection are lost, to ensure privacy is preserved

## Screenshots

Overview: confirmed and available balances, connection progress, and backup status.

![Monero AutoPilot overview showing the wallet companion, connection status, balance, and payment actions](docs/screenshots/overview.jpg)

*Screenshots show the actual app interface with synthetic demo data. The balances, addresses, and transactions pictured are examples; do not send funds to screenshot addresses.*

| Receive | Payment review |
| --- | --- |
| [![Receive view with an address and QR code](docs/screenshots/receive.jpg)](docs/screenshots/receive.jpg) | [![Payment review with the recipient, amount, exact fee, and PIN authorization](docs/screenshots/send-review.jpg)](docs/screenshots/send-review.jpg) |
| Receiving address, QR code, and subaddress creation. | Recipient, amount, calculated network fee, and 4–6 digit PIN authorization. |

| Wallets, backup, and restore | Built-in Tor and reconnection |
| --- | --- |
| [![Wallet management with create, restore, and backup controls](docs/screenshots/wallets.jpg)](docs/screenshots/wallets.jpg) | [![Connection view showing Tor and wallet synchronization status](docs/screenshots/connection.jpg)](docs/screenshots/connection.jpg) |
| Wallet creation, switching, backup verification, and restoration from a 25-word English recovery phrase. | Tor status, node height, wallet synchronization, and retries restricted to permitted routes. |

| Payment activity | Wallet locking |
| --- | --- |
| [![Activity view listing example received and sent payments](docs/screenshots/activity.jpg)](docs/screenshots/activity.jpg) | [![PIN lock screen protecting access to the wallet](docs/screenshots/wallet-lock.jpg)](docs/screenshots/wallet-lock.jpg) |
| Incoming and outgoing transfers, confirmations, and fees. Uncertain send outcomes are reconciled before another send is allowed. | Manual locking, automatic locking after five minutes idle, locking on restart, and PIN authorization for each payment. |

Click any gallery image for the full-size screenshot. [Screenshot notes](docs/screenshots/README.md).

## Architecture

| Component | Implementation |
| --- | --- |
| Desktop shell | Tauri 2 with WebView2 on Windows. |
| Interface | React 19, TypeScript, and Vite; source in [`app/src/`](app/src/). |
| Application host | Rust/Tokio runtime serving the interface and local API to the desktop webview. |
| Wallet process | Local `monero-wallet-rpc`, supervised by [`wallet-rpc`](app/crates/wallet-rpc/). Wallet keys and files are stored locally. |
| Wallet operations | Setup, restore, receive, payment review, submission, and PIN/session handling in [`wallet-runtime`](app/crates/wallet-runtime/). |
| Node transport | Bundled Tor, route policy, and recovery logic in [`autopilot-privacy`](app/crates/autopilot-privacy/). The current configuration connects to an AutoPilot-operated mainnet node. |
| Website | Static HTML, CSS, and JavaScript in [`website/dist/`](website/dist/). |

Runtime setup scripts verify upstream Monero and Tor downloads using signatures and pinned checksums. Runtime binaries, wallet files, credentials, and generated QA reports are excluded from Git.

## Build and test

The Windows build requires Node.js 24+, pnpm 11.25.0, the Rust MSVC toolchain, Visual Studio C++ Build Tools, a Windows SDK, and WebView2.

See the [app development guide](app/README.md) for dependency setup, runtime preparation, builds, frontend tests, Rust tests, and NSIS packaging. See the [website guide](website/README.md) for local preview and publishing instructions.

## Release status

The current **0.9.0 preview** is an unsigned Windows x64 installer connected to Monero mainnet. Payments are capped at **0.01 XMR per transfer**, with a maximum network fee of **0.0001 XMR**. macOS and Linux builds are not currently distributed.

The [download page](https://moneroautopilot.com/downloads.html) contains the installer, SHA-256 checksum, and release notes. Installers are distributed separately from the source repository.

## Contributions welcome

Contributions can address wallet behavior, connection recovery, accessibility, documentation, automated tests, installer validation, or macOS/Linux support.

Use [issues](https://github.com/DeadKennedyx/monero-autopilot/issues) for reproducible bug reports and proposed changes, or submit a [pull request](https://github.com/DeadKennedyx/monero-autopilot/pulls). Include the affected version, reproduction steps, expected and actual behavior, and relevant validation. Discuss larger changes in an issue first.

Use synthetic data in examples and tests. Do not include recovery phrases, private keys, real PINs, wallet files, credentials, or private logs.

## Node donations

Optional XMR donations fund hosting for the AutoPilot-operated Monero node. Donations do not affect access to wallet features.

[Donation page](https://moneroautopilot.com/donate.html)

Monero mainnet donation address:

```text
48WR4Mfg7QuDhZFF1ZvRwA5sBN532ESqiXq5b2fcJoZjWt6HkJ99ouWFuVFd9nepxvc6hLH1WdhkdNwNggnmvLKtMPKi2e9
```

<a href="https://moneroautopilot.com/donate.html"><img src="website/dist/donation-qr.svg" alt="Monero mainnet node donation QR code" width="200"></a>

## Repository

- **[app/](app/)** — Tauri desktop application, React interface, Rust wallet runtime, build scripts, and automated tests.
- **[website/](website/)** — landing, download, and donation pages with local assets.
- **[docs/screenshots/](docs/screenshots/)** — app screenshots captured using synthetic demo data.

## License

[MIT](LICENSE). Bundled upstream components retain their respective licenses. Monero AutoPilot is an independent project and is not an official Monero wallet or an endorsement by the Monero Project.

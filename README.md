# Monero AutoPilot

Source for the Monero AutoPilot desktop wallet and its public website.

- **[app/](app/)** — Windows Tauri application, React interface, Rust wallet runtime, build scripts and automated tests.
- **[website/](website/)** — landing and download pages, including their local assets and preview server.

The desktop application connects to Monero mainnet through built-in Tor. Wallet setup, backup and restore, receiving, payment review, PIN authorization and automatic reconnection live in the app. The app keeps wallet data on the user's computer.

See [app/README.md](app/README.md) for development and installer instructions, and [website/README.md](website/README.md) to preview the website.

This repository contains product source. Standalone component prototypes, wallet files, credentials, runtime downloads and generated QA reports are excluded. Downloadable installers are separate release artifacts.

License: [MIT](LICENSE). Bundled upstream components retain their respective licenses.

Visit [moneroautopilot.com](https://moneroautopilot.com) for the app, or [support the node](https://moneroautopilot.com/donate.html) with an optional XMR donation toward hosting costs.

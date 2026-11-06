# App screenshots

Captured on November 6, 2026 from the packaged Monero AutoPilot 0.9.0 frontend. The interface uses the same React components, styling, and companion as the Windows Tauri app.

These images use an isolated localhost UI fixture with fabricated balances, wallet names, addresses, transaction IDs, and connection observations. No native wallet, Tor process, node, payment, recovery phrase, or real PIN was used in the capture session. The receiving address and QR code in the app screenshots are placeholders and must not be used for payments.

The node donation QR in the repository README is separate: it is the public mainnet donation address published on [the donation page](https://moneroautopilot.com/donate.html).

| Image | Feature |
| --- | --- |
| [Overview](overview.jpg) | Connection readiness, balances, backup status, and the companion |
| [Receive](receive.jpg) | Receiving address, QR code, and fresh address creation |
| [Payment review](send-review.jpg) | Recipient, exact amount and fee, and PIN authorization |
| [Wallets](wallets.jpg) | Multiple wallets, backup review, creation, and restoration |
| [Connection](connection.jpg) | Built-in Tor, node status, and synchronization details |
| [Activity](activity.jpg) | Incoming and outgoing payment history |
| [Wallet lock](wallet-lock.jpg) | PIN-based access to the app |

When refreshing these screenshots, capture the current app UI with synthetic fixtures, inspect every image for private data, and update the README descriptions if behavior changes. Keep private runtime folders and wallet data out of Git.

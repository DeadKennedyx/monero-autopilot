# Monero AutoPilot website

Static landing, download, and node donation pages. Public files are in `dist/`; no build step or package installation is needed.

## Local preview

From this directory, run:

```sh
node preview.mjs
```

Open the localhost URL printed in the terminal. The server listens only on this computer; stop it with Ctrl+C.

## Publishing

Publish the contents of `dist/` as the root of a static website. The entry pages are `/`, `/downloads.html`, and `/donate.html`; asset links are relative to the site root. `preview.mjs` is only for local review.

After changing styles, scripts, or the donation QR, run `node version-assets.mjs` before previewing and publishing. It updates content-based asset URLs in all three pages so returning visitors do not receive an older cached stylesheet or script.

The Windows download button links to the unsigned 0.9.0 preview on `downloads.moneroautopilot.com`. The page describes its signing status and payment limits. Release metadata is tracked in `releases/0.9.0-preview.1.json`; the installer and checksum file are deployed separately to Hetzner and are not stored in Git.

Publish versioned artifacts first, verify their public HTTPS download and SHA-256, then publish the website. Never replace an existing versioned artifact with different bytes: downloads are cached as immutable. The website uses an atomic `current` symlink on the existing Hetzner host so a previous website release can be restored. Credentials and private deployment records stay outside the tracked website.

The interactive wallet tour uses fabricated balances and has no wallet connection. It never accepts PINs or recovery phrases. Assets, scripts, and styles are local; there are no analytics or external font requests.

The donation page contains only the public mainnet receiving address and a locally generated QR code containing the same `monero:` URI. The copy button copies that address; it never initiates a payment. The donation wallet, password, and recovery phrase are stored privately outside this repository and must never be included in a deployment.

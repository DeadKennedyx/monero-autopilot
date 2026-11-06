# Monero AutoPilot website

Static landing page and download-page design. The six public files are in `dist/`; no build step or package installation is needed.

## Local preview

From this directory, run:

```sh
node preview.mjs
```

Open the localhost URL printed in the terminal. The server listens only on this computer; stop it with Ctrl+C.

## Publishing

Publish the contents of `dist/` as the root of a static website. The entry pages are `/` and `/downloads.html`; asset links are relative to the site root. `preview.mjs` is only for local review.

The Windows download button links to the unsigned 0.9.0 preview on `downloads.moneroautopilot.com`. The page describes its signing status and payment limits. Release metadata is tracked in `releases/0.9.0-preview.1.json`; the installer and checksum file are deployed separately to Hetzner and are not stored in Git.

Publish versioned artifacts first, verify their public HTTPS download and SHA-256, then publish the website. Never replace an existing versioned artifact with different bytes: downloads are cached as immutable. The website uses an atomic `current` symlink on the existing Hetzner host so a previous website release can be restored. Credentials and private deployment records stay outside the tracked website.

The interactive wallet tour uses fabricated balances and has no wallet connection. It never accepts PINs or recovery phrases. Assets, scripts, and styles are local; there are no analytics or external font requests.

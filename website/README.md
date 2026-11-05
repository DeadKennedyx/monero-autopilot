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

The Windows download button remains disabled until a verified installer is explicitly attached for launch. This copy does not activate downloads or include release files or deployment credentials.

The interactive wallet tour uses fabricated balances and has no wallet connection. It never accepts PINs or recovery phrases. Assets, scripts, and styles are local; there are no analytics or external font requests.

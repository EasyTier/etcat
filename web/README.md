# etcat web

Browser UI for etcat: send and receive files or text peer-to-peer through the
EasyTier WebAssembly runtime. Vue 3 + Vite + Tailwind CSS 4 + Reka UI.

## Develop

```console
pnpm install
pnpm dev        # http://localhost:5173
```

## Build and serve

```console
pnpm build
python3 -m http.server 8000 --directory dist
```

The page must be served over HTTPS or `localhost` (WebCrypto requirement).
HTTPS pages can only reach `wss://` relays; the default `community-1` relay
ships a publicly trusted WSS endpoint, so no configuration is needed.

## Runtime vendoring

The EasyTier browser runtime is vendored, not published as a package:

- `vendor/runtime/` holds the TypeScript closure of
  `easytier-contrib/easytier-cloudflare-worker`'s browser library
  (`browser/lib.ts` and everything it imports),
- `public/easytier_core.wasm` is the browser-profile EasyTier core build.

Both are committed so the app builds standalone. Refresh them after upstream
changes:

```console
# In the EasyTier checkout first:
#   cd easytier-contrib/easytier-cloudflare-worker && pnpm build:browser-wasm
pnpm sync:runtime -- --from /path/to/EasyTier
```

The source revision and per-file SHA-256 land in
`vendor/runtime/MANIFEST.json`; review the diff before committing.

## Smoke-test hooks

The page keeps the automation contract used by the EasyTier browser smoke
harness:

- `?mode=listen` starts a listener on load;
- `?mode=send&token=etc2...&bytes=N` sends `N` random bytes;
- `?sink=hash` hashes received payloads into `window.etcatTest` instead of
  showing transfer cards;
- `?relay=` and `?relayKey=` override the stored relay settings;
- `?token=etc2...` (share link) switches to the Send tab with the token
  prefilled.

`window.etcatTest` exposes `ready`, `listenToken`, `recvBytes`, `recvHash`,
`recvDone`, `sentBytes`, `sentHash`, `sentDone`, and `errors`.

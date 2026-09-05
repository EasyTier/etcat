# etcat web

Browser UI for etcat: send and receive files or text peer-to-peer through the
EasyTier WebAssembly runtime. Vue 3 + Vite + Tailwind CSS 4 + Reka UI.

## Develop

```console
pnpm install
pnpm dev        # http://localhost:5173
```

## Behavior notes

- **Auto-receive**: incoming payloads start buffering immediately (no
  accept/decline step) so the sender sees progress at once. Valid UTF-8
  payloads render as text with a copy button; everything else gets a Save
  button backed by the in-memory buffer (File System Access API when
  available, Blob download otherwise). Payloads over 512 MiB are rejected
  with a clear error instead of exhausting memory.
- **i18n**: the UI ships Chinese and English; it follows the browser language
  by default, toggles in the header, persists to `localStorage`, and can be
  forced with `?lang=zh|en`.

## Build and serve

```console
pnpm build
python3 -m http.server 8000 --directory dist
```

The page must be served over HTTPS or `localhost` (WebCrypto requirement).
HTTPS pages can only reach `wss://` relays; the default `community-1` relay
ships a publicly trusted WSS endpoint, so no configuration is needed.

## Troubleshooting

- **"Timed out" on every send**: you are almost certainly running a stale
  build. Run `pnpm build` again and hard-refresh (`Ctrl+Shift+R`) — the
  current version retries relay route sync for 30 s instead of failing after
  a single 5 s attempt.
- **Nothing connects on an HTTPS deployment**: the relay must be `wss://`.
  The default `community-1` already is; a custom `ws://` relay only works on
  `http://localhost` pages.
- **Relay unreachable at all**: check the browser console for
  `connect_error` events and try `?relay=wss://<your-relay>` once to isolate
  the community relay from your network path.

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

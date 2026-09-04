#!/usr/bin/env node
// Syncs the browser-compatible EasyTier runtime (TypeScript sources plus the
// WASI wasm build) from an EasyTier checkout into vendor/runtime.
//
//   node scripts/sync-runtime.mjs --from /path/to/EasyTier
//
// The checkout must contain easytier-contrib/easytier-cloudflare-worker with
// the browser profile wasm already built (`pnpm build:browser-wasm` there).
// Vendored files are committed so the web app builds standalone; re-run this
// script to pick up upstream runtime changes.

import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const WEB_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VENDOR_DIR = join(WEB_ROOT, "vendor", "runtime");
const PACKAGE_DIR = join(
  "easytier-contrib",
  "easytier-cloudflare-worker",
);

const RUNTIME_FILES = [
  join(PACKAGE_DIR, "browser", "etcat-client.ts"),
  join(PACKAGE_DIR, "browser", "etcat-server.ts"),
  join(PACKAGE_DIR, "browser", "etcat-relays.generated.ts"),
  join(PACKAGE_DIR, "browser", "host.ts"),
  join(PACKAGE_DIR, "browser", "transfer.ts"),
  join(PACKAGE_DIR, "browser", "lib.ts"),
  join(PACKAGE_DIR, "src", "core-runtime.ts"),
  join(PACKAGE_DIR, "src", "data-plane.ts"),
  join(PACKAGE_DIR, "src", "websocket-host.ts"),
  join(PACKAGE_DIR, "src", "wasi-clock.ts"),
  join(PACKAGE_DIR, "src", "wasi-preview1.ts"),
  join(PACKAGE_DIR, "src", "jspi.d.ts"),
];

const WASM_FILE = join(
  PACKAGE_DIR,
  "browser",
  "generated",
  "easytier_core.wasm",
);

function parseArgs(argv) {
  let from = process.env.EASYTIER_CHECKOUT;
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--from") {
      from = argv[i + 1];
      i += 1;
    } else {
      throw new Error(`unknown argument: ${argv[i]}`);
    }
  }
  if (from === undefined) {
    throw new Error(
      "usage: node scripts/sync-runtime.mjs --from /path/to/EasyTier " +
        "(or set EASYTIER_CHECKOUT)",
    );
  }
  return resolve(from);
}

function gitRevision(checkout) {
  try {
    return execFileSync("git", ["-C", checkout, "rev-parse", "HEAD"], {
      encoding: "utf8",
    }).trim();
  } catch {
    return "unknown";
  }
}
async function main() {
  const checkout = parseArgs(process.argv.slice(2));
  const manifest = {
    source: checkout,
    revision: gitRevision(checkout),
    syncedAt: new Date().toISOString(),
    files: {},
  };

  const copy = async (source, target) => {
    const bytes = await readFile(source);
    await mkdir(dirname(target), { recursive: true });
    await copyFile(source, target);
    return bytes;
  };

  for (const relative of RUNTIME_FILES) {
    const bytes = await copy(
      join(checkout, relative),
      join(VENDOR_DIR, relative),
    ).catch(() => {
      throw new Error(`missing ${relative} in ${checkout}`);
    });
    manifest.files[relative] = createHash("sha256").update(bytes).digest("hex");
  }

  // The wasm is served as a static asset from public/, not vendored with the
  // TypeScript sources.
  const wasmBytes = await copy(
    join(checkout, WASM_FILE),
    join(WEB_ROOT, "public", "easytier_core.wasm"),
  ).catch(() => {
    throw new Error(
      `missing ${WASM_FILE} in ${checkout}; ` +
        "run `pnpm build:browser-wasm` in the EasyTier checkout first",
    );
  });
  manifest.files[WASM_FILE] = createHash("sha256").update(wasmBytes).digest("hex");
  await writeFile(
    join(VENDOR_DIR, "MANIFEST.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  console.log(
    `vendored ${RUNTIME_FILES.length} sources + wasm from ${checkout} ` +
      `(${manifest.revision})`,
  );
}

await main();

import type { EtcatRelay } from "./etcat-client";
import type { EtcatBrowserServerKey } from "./etcat-server";

const SERVER_KEY_STORAGE = "etcat-browser-server-key-v1";

export interface ServerKeyStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export function browserRelayFromInput(
  input: string,
  publicKey: string,
  pageProtocol: string,
): EtcatRelay {
  const value = input.trim();
  if (value.length === 0) {
    throw new Error(
      "Enter an EasyTier relay with a WebSocket endpoint before listening",
    );
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`Invalid relay URL: ${value}`);
  }
  if (url.protocol !== "ws:" && url.protocol !== "wss:") {
    throw new Error("Browser relays must use ws:// or wss://");
  }
  if (pageProtocol === "https:" && url.protocol !== "wss:") {
    throw new Error("HTTPS pages can only connect to wss:// relays");
  }
  const pin = publicKey.trim();
  return {
    id: "browser-custom",
    endpoints: [url.toString()],
    ...(pin.length === 0 ? {} : { publicKey: pin }),
  };
}

export function loadPersistentServerKey(
  storage: ServerKeyStorage,
): EtcatBrowserServerKey | undefined {
  const encoded = storage.getItem(SERVER_KEY_STORAGE);
  if (encoded === null) {
    return undefined;
  }
  let value: unknown;
  try {
    value = JSON.parse(encoded);
  } catch {
    throw new Error("The stored etcat listener key is not valid JSON");
  }
  if (!isServerKey(value)) {
    throw new Error("The stored etcat listener key has an invalid shape");
  }
  return value;
}

export function storePersistentServerKey(
  storage: ServerKeyStorage,
  key: EtcatBrowserServerKey,
): void {
  storage.setItem(SERVER_KEY_STORAGE, JSON.stringify(key));
}

function isServerKey(value: unknown): value is EtcatBrowserServerKey {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const key = value as Record<string, unknown>;
  return key.version === 1 &&
    typeof key.signingPrivateKeyPkcs8 === "string" &&
    typeof key.signingPublicKey === "string" &&
    typeof key.noisePrivateKey === "string" &&
    typeof key.networkSecret === "string" &&
    typeof key.bearerSeed === "string" &&
    (key.gatewayPort === undefined ||
      (Number.isInteger(key.gatewayPort) &&
        (key.gatewayPort as number) >= 1 &&
        (key.gatewayPort as number) <= 65_535));
}

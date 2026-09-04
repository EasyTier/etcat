import { reactive, watch } from "vue";
import { defaultRelayUrl } from "./runtime";

const SETTINGS_STORAGE = "etcat-web-settings-v1";

export interface Settings {
  relayUrl: string;
  relayKey: string;
  persistListenerKey: boolean;
}

function defaults(): Settings {
  return {
    relayUrl: defaultRelayUrl(),
    relayKey: "",
    persistListenerKey: false,
  };
}

function load(): Settings {
  const base = defaults();
  const params = new URLSearchParams(window.location.search);
  const stored = window.localStorage.getItem(SETTINGS_STORAGE);
  if (stored !== null) {
    try {
      const parsed = JSON.parse(stored) as Partial<Settings>;
      if (typeof parsed.relayUrl === "string") base.relayUrl = parsed.relayUrl;
      if (typeof parsed.relayKey === "string") base.relayKey = parsed.relayKey;
      if (typeof parsed.persistListenerKey === "boolean") {
        base.persistListenerKey = parsed.persistListenerKey;
      }
    } catch {
      // Corrupt settings fall back to defaults.
    }
  }
  // Query parameters win over stored settings (smoke harness + share links).
  const relay = params.get("relay");
  if (relay !== null) base.relayUrl = relay;
  const relayKey = params.get("relayKey");
  if (relayKey !== null) base.relayKey = relayKey;
  return base;
}

export const settings = reactive<Settings>(load());

watch(settings, (value) => {
  window.localStorage.setItem(SETTINGS_STORAGE, JSON.stringify(value));
});

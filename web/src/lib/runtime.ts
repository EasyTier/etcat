// Thin typed facade over the vendored EasyTier browser runtime. Application
// code imports from here so the vendor path stays in one place.

export {
  BUILTIN_ETCAT_RELAY_REGISTRY,
  browserRelayFromInput,
  connectEtcatBrowser,
  drainPayload,
  etcatListen,
  loadPersistentServerKey,
  openEtcatStream,
  sha256Hex,
  storePersistentServerKey,
  transferPayload,
  type EtcatBrowserConnection,
  type EtcatBrowserIncomingConnection,
  type EtcatBrowserServer,
  type EasyTierCoreEvent,
  type EasyTierTcpStream,
  type EtcatRelay,
  type PayloadReader,
} from "@runtime/easytier-contrib/easytier-cloudflare-worker/browser/lib";

import { browserRelayFromInput } from "@runtime/easytier-contrib/easytier-cloudflare-worker/browser/lib";

// The checked-in community relay ships a publicly trusted WSS endpoint; use it
// as the zero-config default for HTTPS pages.
export function defaultRelayUrl(): string {
  return "wss://relay.38-76-179-190.sslip.io/";
}

export function relayFromSettings(
  url: string,
  publicKey: string,
  pageProtocol: string,
) {
  return browserRelayFromInput(url, publicKey, pageProtocol);
}

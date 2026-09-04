import { EasyTierRuntime } from "../src/core-runtime";
import type {
  EasyTierTcpListener,
  EasyTierTcpStream,
} from "../src/data-plane";
import type { EasyTierCoreEvent } from "../src/websocket-host";
import {
  BUILTIN_ETCAT_RELAY_REGISTRY,
  CLIENT_AUTH_DOMAIN,
  GATEWAY_AUTHENTICATION_INFO,
  canonicalEtcatDestination,
  concatBytes,
  currentPageProtocol,
  decodeBase64,
  decodeCbor,
  deriveCredentialKey,
  encodeBase64,
  encodeCborMap,
  encodeU32,
  escapeToml,
  formatUuid,
  gatewayTranscript,
  hex,
  ownedBytes,
  readFrame,
  requireCborMap,
  selectBrowserRelay,
  validateRelayRegistry,
  writeFrame,
  type CborValue,
  type EtcatDestination,
  type EtcatRelay,
  type EtcatRelayRegistry,
  type OwnedBytes,
} from "./etcat-client";

const SERVER_KEY_VERSION = 1;
const TOKEN_PREFIX = "etc2";
const TOKEN_EXPIRY_FLAG = 0x10;
const MAX_ENCODED_TOKEN_LENGTH = 16 * 1024;
const REGISTRY_CODE_RELAY = 0;
const REGISTRY_RELAY = 1;
const INLINE_RELAY = 2;
const CLIENT_GROUP = "etcat-client";
const EASYTIER_CREDENTIAL_INFO = new TextEncoder().encode(
  "easytier x25519 private key",
);
const DEFAULT_MAX_CONNECTIONS = 256;
const DEFAULT_HANDSHAKE_TIMEOUT_MILLISECONDS = 5000;
const FIRST_EPHEMERAL_PORT = 49_152;
const EPHEMERAL_PORT_COUNT = 16_384;
const NO_CREDENTIAL_EXPIRY = "9223372036854775807";

export interface EtcatBrowserServerKey {
  version: 1;
  signingPrivateKeyPkcs8: string;
  signingPublicKey: string;
  noisePrivateKey: string;
  networkSecret: string;
  bearerSeed: string;
  gatewayPort?: number;
}

export interface EtcatBrowserIncomingConnection {
  destination: EtcatDestination;
  stream: EasyTierTcpStream;
}

export type EtcatBrowserDestinationAuthorization =
  | boolean
  | string;

export interface EtcatBrowserListenOptions {
  relay?: string | EtcatRelay;
  relayRegistry?: EtcatRelayRegistry;
  key?: EtcatBrowserServerKey;
  gatewayPort?: number;
  ttlSeconds?: number;
  fullAddress?: boolean;
  maxConnections?: number;
  handshakeTimeoutMilliseconds?: number;
  authorize?: (
    destination: EtcatDestination,
  ) =>
    | EtcatBrowserDestinationAuthorization
    | Promise<EtcatBrowserDestinationAuthorization>;
  onConnection: (
    connection: EtcatBrowserIncomingConnection,
  ) => void | Promise<void>;
  onError?: (error: unknown) => void;
  onEvent?: (event: EasyTierCoreEvent) => void;
}

interface LoadedServerKey {
  persisted: EtcatBrowserServerKey;
  signingPrivateKey: CryptoKey;
  signingPublicKey: CryptoKey;
  signingPublicBytes: OwnedBytes;
  noisePrivateKey: OwnedBytes;
  networkSecret: OwnedBytes;
  bearerSeed: OwnedBytes;
}

interface ServerIdentity {
  fingerprint: OwnedBytes;
  networkName: string;
  gatewayIpv4: string;
}

interface RelaySelection {
  relay: EtcatRelay;
  relayUrl: string;
  locator: RelayLocator;
}

type RelayLocator =
  | { kind: "registry_code"; code: number }
  | { kind: "registry"; id: string }
  | { kind: "inline"; relay: EtcatRelay };

export async function etcatListen(
  module: WebAssembly.Module,
  options: EtcatBrowserListenOptions,
): Promise<EtcatBrowserServer> {
  return EtcatBrowserServer.listen(module, options);
}

export class EtcatBrowserServer {
  readonly runtime: EasyTierRuntime;
  readonly token: string;
  readonly key: EtcatBrowserServerKey;
  readonly networkName: string;
  readonly gatewayIpv4: string;
  readonly gatewayPort: number;

  private readonly listener: EasyTierTcpListener;
  private readonly loadedKey: LoadedServerKey;
  private readonly expiresUnix: number | undefined;
  private readonly options: EtcatBrowserListenOptions;
  private readonly activeStreams = new Set<EasyTierTcpStream>();
  private readonly connectionTasks = new Set<Promise<void>>();
  private acceptTask: Promise<void> | undefined;
  private closePromise: Promise<void> | undefined;
  private closing = false;

  private constructor(
    runtime: EasyTierRuntime,
    listener: EasyTierTcpListener,
    token: string,
    key: EtcatBrowserServerKey,
    loadedKey: LoadedServerKey,
    identity: ServerIdentity,
    expiresUnix: number | undefined,
    options: EtcatBrowserListenOptions,
  ) {
    this.runtime = runtime;
    this.listener = listener;
    this.token = token;
    this.key = key;
    this.loadedKey = loadedKey;
    this.networkName = identity.networkName;
    this.gatewayIpv4 = identity.gatewayIpv4;
    this.gatewayPort = key.gatewayPort!;
    this.expiresUnix = expiresUnix;
    this.options = options;
  }

  static async listen(
    module: WebAssembly.Module,
    options: EtcatBrowserListenOptions,
  ): Promise<EtcatBrowserServer> {
    validateOptions(options);
    const loadedKey = options.key === undefined
      ? await generateServerKey()
      : await loadServerKey(options.key);
    const identity = await serverIdentity(loadedKey.signingPublicBytes);
    const registry = options.relayRegistry ?? BUILTIN_ETCAT_RELAY_REGISTRY;
    const relay = selectRelay(options.relay, registry, options.fullAddress ?? false);
    const gatewayPort = selectGatewayPort(options, loadedKey.persisted);
    const expiresUnix = expiryFromTtl(options.ttlSeconds);
    const key: EtcatBrowserServerKey = {
      ...loadedKey.persisted,
      gatewayPort,
    };
    loadedKey.persisted = key;
    const token = encodeConnectionToken(
      identity.fingerprint,
      gatewayPort,
      expiresUnix,
      loadedKey.bearerSeed,
      relay.locator,
    );
    const credentialSecret = encodeBase64(
      await deriveCredentialKey(
        loadedKey.bearerSeed,
        EASYTIER_CREDENTIAL_INFO,
      ),
    );
    const config = await serverConfig(
      identity,
      loadedKey,
      credentialSecret,
      relay,
      gatewayPort,
      expiresUnix,
    );
    const runtime = new EasyTierRuntime(
      module,
      config,
      (url) => new WebSocket(url),
      options.onEvent,
    );
    let listener: EasyTierTcpListener;
    try {
      await runtime.ready;
      listener = await runtime.bindTcp(gatewayPort, 5000);
    } catch (error) {
      await runtime.stop().catch(() => undefined);
      throw error;
    }
    if (
      listener.localAddress.ipv4 !== identity.gatewayIpv4 ||
      listener.localAddress.port !== gatewayPort
    ) {
      await listener.close().catch(() => undefined);
      await runtime.stop().catch(() => undefined);
      throw new Error(
        `EasyTier bound browser gateway ${listener.localAddress.ipv4}:${listener.localAddress.port}, expected ${identity.gatewayIpv4}:${gatewayPort}`,
      );
    }
    const server = new EtcatBrowserServer(
      runtime,
      listener,
      token,
      key,
      loadedKey,
      identity,
      expiresUnix,
      options,
    );
    server.acceptTask = server.acceptConnections();
    return server;
  }

  close(): Promise<void> {
    if (this.closePromise !== undefined) {
      return this.closePromise;
    }
    this.closing = true;
    this.closePromise = this.closeResources();
    return this.closePromise;
  }

  private async closeResources(): Promise<void> {
    await this.listener.close().catch(() => undefined);
    await Promise.allSettled(
      Array.from(this.activeStreams, (stream) => stream.close()),
    );
    await this.runtime.stop();
    await this.acceptTask?.catch(() => undefined);
  }

  private async acceptConnections(): Promise<void> {
    const maxConnections = this.options.maxConnections ?? DEFAULT_MAX_CONNECTIONS;
    while (!this.closing) {
      let stream: EasyTierTcpStream;
      try {
        stream = await this.listener.accept();
      } catch (error) {
        if (!this.closing) {
          this.reportError(error);
        }
        return;
      }
      if (this.closing || this.connectionTasks.size >= maxConnections) {
        await stream.close().catch(() => undefined);
        continue;
      }
      this.activeStreams.add(stream);
      let task: Promise<void>;
      task = this.handleConnection(stream)
        .catch((error: unknown) => {
          if (!this.closing) {
            this.reportError(error);
          }
        })
        .finally(() => {
          this.activeStreams.delete(stream);
          this.connectionTasks.delete(task);
        });
      this.connectionTasks.add(task);
    }
  }

  private async handleConnection(stream: EasyTierTcpStream): Promise<void> {
    try {
      const destination = await withTimeout(
        this.authenticate(stream),
        this.options.handshakeTimeoutMilliseconds ??
          DEFAULT_HANDSHAKE_TIMEOUT_MILLISECONDS,
        "etcat gateway request timed out",
      );
      if (destination.kind !== "ping") {
        await this.options.onConnection({ destination, stream });
      }
    } catch (error) {
      if (!isHandshakeRejection(error)) {
        throw error;
      }
    } finally {
      await stream.close().catch(() => undefined);
    }
  }

  private async authenticate(stream: EasyTierTcpStream): Promise<EtcatDestination> {
    const requestBytes = await readFrame(stream);
    const request = decodeGatewayRequest(requestBytes);
    const authenticationBytes = encodeCborMap([
      ["domain", Array.from(CLIENT_AUTH_DOMAIN)],
      ["network_name", this.networkName],
      ["version", request.version],
      ["nonce", request.nonce],
      ["destination", canonicalEtcatDestination(request.destination)],
    ]);
    const authenticationKey = await deriveCredentialKey(
      this.loadedKey.bearerSeed,
      GATEWAY_AUTHENTICATION_INFO,
    );
    const hmacKey = await crypto.subtle.importKey(
      "raw",
      authenticationKey,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const authenticated = await crypto.subtle.verify(
      "HMAC",
      hmacKey,
      ownedBytes(request.authenticator),
      authenticationBytes,
    );
    let rejection: string | undefined;
    if (
      this.expiresUnix !== undefined &&
      Math.floor(Date.now() / 1000) >= this.expiresUnix
    ) {
      rejection = "client credential has expired";
    } else if (!authenticated) {
      rejection = "client authentication failed";
    } else {
      rejection = await authorizationRejection(
        this.options.authorize,
        request.destination,
      );
    }
    await writeGatewayResponse(
      stream,
      this.networkName,
      requestBytes,
      this.loadedKey,
      rejection,
    );
    if (rejection !== undefined) {
      throw new HandshakeRejection(rejection);
    }
    return request.destination;
  }

  private reportError(error: unknown): void {
    if (this.options.onError !== undefined) {
      try {
        this.options.onError(error);
      } catch (callbackError) {
        console.error("etcat browser server onError callback failed", callbackError);
      }
      return;
    }
    console.error("etcat browser server connection failed", error);
  }
}

class HandshakeRejection extends Error {}

function isHandshakeRejection(error: unknown): error is HandshakeRejection {
  return error instanceof HandshakeRejection;
}

async function generateServerKey(): Promise<LoadedServerKey> {
  const signing = await crypto.subtle.generateKey(
    "Ed25519",
    true,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  const signingPrivateKeyPkcs8 = new Uint8Array(
    await crypto.subtle.exportKey("pkcs8", signing.privateKey) as ArrayBuffer,
  );
  const signingPublicBytes = new Uint8Array(
    await crypto.subtle.exportKey("raw", signing.publicKey) as ArrayBuffer,
  );
  const noisePrivateKey = secureRandomBytes(32);
  const networkSecret = secureRandomBytes(32);
  const bearerSeed = secureRandomBytes(16);
  return {
    persisted: {
      version: SERVER_KEY_VERSION,
      signingPrivateKeyPkcs8: encodeBase64(signingPrivateKeyPkcs8),
      signingPublicKey: encodeBase64(signingPublicBytes),
      noisePrivateKey: encodeBase64(noisePrivateKey),
      networkSecret: encodeBase64(networkSecret),
      bearerSeed: encodeBase64(bearerSeed),
    },
    signingPrivateKey: signing.privateKey,
    signingPublicKey: signing.publicKey,
    signingPublicBytes,
    noisePrivateKey,
    networkSecret,
    bearerSeed,
  };
}

async function loadServerKey(
  persisted: EtcatBrowserServerKey,
): Promise<LoadedServerKey> {
  if (persisted.version !== SERVER_KEY_VERSION) {
    throw new Error(`unsupported etcat browser server key version ${String(persisted.version)}`);
  }
  if (persisted.gatewayPort !== undefined) {
    validatePort(persisted.gatewayPort, "persisted gateway");
  }
  const signingPrivateBytes = decodeCanonicalBase64(
    persisted.signingPrivateKeyPkcs8,
    "signing private key",
  );
  const signingPublicBytes = decodeFixedBase64(
    persisted.signingPublicKey,
    32,
    "signing public key",
  );
  const noisePrivateKey = decodeFixedBase64(
    persisted.noisePrivateKey,
    32,
    "Noise private key",
  );
  const networkSecret = decodeFixedBase64(
    persisted.networkSecret,
    32,
    "network secret",
  );
  const bearerSeed = decodeFixedBase64(
    persisted.bearerSeed,
    16,
    "bearer credential seed",
  );
  const signingPrivateKey = await crypto.subtle.importKey(
    "pkcs8",
    signingPrivateBytes,
    "Ed25519",
    false,
    ["sign"],
  );
  const signingPublicKey = await crypto.subtle.importKey(
    "raw",
    signingPublicBytes,
    "Ed25519",
    false,
    ["verify"],
  );
  const probe = new TextEncoder().encode("etcat browser server key check");
  const signature = await crypto.subtle.sign(
    "Ed25519",
    signingPrivateKey,
    probe,
  );
  if (!(await crypto.subtle.verify("Ed25519", signingPublicKey, signature, probe))) {
    throw new Error("etcat browser signing public and private keys do not match");
  }
  return {
    persisted: { ...persisted },
    signingPrivateKey,
    signingPublicKey,
    signingPublicBytes,
    noisePrivateKey,
    networkSecret,
    bearerSeed,
  };
}

async function serverIdentity(publicKey: OwnedBytes): Promise<ServerIdentity> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey));
  const fingerprint = digest.subarray(0, 16);
  const networkName = `etcat-${hex(fingerprint)}`;
  const networkDigest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(networkName)),
  );
  return {
    fingerprint,
    networkName,
    gatewayIpv4: `100.${64 + (networkDigest[0]! % 64)}.${networkDigest[1]}.${networkDigest[2]}`,
  };
}

async function serverConfig(
  identity: ServerIdentity,
  key: LoadedServerKey,
  credentialSecret: string,
  relay: RelaySelection,
  gatewayPort: number,
  expiresUnix: number | undefined,
): Promise<string> {
  const instanceDigest = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      concatBytes(key.signingPublicBytes, key.noisePrivateKey),
    ),
  );
  const relayPublicKey = relay.relay.publicKey === undefined
    ? ""
    : `\npeer_public_key = "${escapeToml(relay.relay.publicKey)}"`;
  return `
instance_id = "${formatUuid(instanceDigest.subarray(0, 16))}"
instance_name = "etcat-browser-server"
ipv4 = "${identity.gatewayIpv4}/24"
listeners = []

[network_identity]
network_name = "${identity.networkName}"
network_secret = "${escapeToml(encodeBase64(key.networkSecret))}"

[secure_mode]
enabled = true
local_private_key = "${escapeToml(encodeBase64(key.noisePrivateKey))}"

[[peer]]
uri = "${escapeToml(relay.relayUrl)}"${relayPublicKey}

[[managed_credentials]]
credential_id = "etcat-default"
credential_secret = "${escapeToml(credentialSecret)}"
groups = ["${CLIENT_GROUP}"]
allow_relay = false
expiry_unix = ${expiresUnix ?? NO_CREDENTIAL_EXPIRY}
reusable = false

[[acl.acl_v1.chains]]
name = "etcat-inbound"
chain_type = 1
description = "Token-scoped browser gateway access"
enabled = true
default_action = 2

[[acl.acl_v1.chains.rules]]
name = "etcat-token-inbound"
description = "Allow only the issued browser gateway"
priority = 1000
enabled = true
protocol = 1
ports = ["${gatewayPort}"]
destination_ips = ["${identity.gatewayIpv4}/32"]
source_groups = ["${CLIENT_GROUP}"]
action = 1
stateful = true

[flags]
no_tun = true
use_smoltcp = true
disable_p2p = true
enable_encryption = true
bind_device = false
`;
}

function selectRelay(
  requested: string | EtcatRelay | undefined,
  registry: EtcatRelayRegistry,
  fullAddress: boolean,
): RelaySelection {
  validateRelayRegistry(registry);
  let relay: EtcatRelay;
  if (typeof requested === "string") {
    const found = registry.relays.find((candidate) => candidate.id === requested);
    if (found === undefined) {
      throw new Error(`relay ${JSON.stringify(requested)} is not in the browser relay registry`);
    }
    relay = found;
  } else if (requested !== undefined) {
    relay = requested;
  } else {
    const found = registry.relays.find((candidate) =>
      candidate.endpoints.some((endpoint) => {
        try {
          const protocol = new URL(endpoint).protocol;
          return protocol === "wss:" ||
            (protocol === "ws:" && currentPageProtocol() !== "https:");
        } catch {
          return false;
        }
      })
    );
    if (found === undefined) {
      throw new Error("browser relay registry has no usable ws:// or wss:// relay");
    }
    relay = found;
  }
  validateRelay(relay);
  const relayUrl = selectBrowserRelay(relay.endpoints, currentPageProtocol());
  const registryRelay = registry.relays.find((candidate) =>
    sameRelay(candidate, relay)
  );
  let locator: RelayLocator;
  if (!fullAddress && registryRelay !== undefined) {
    locator = registryRelay.tokenId === undefined
      ? { kind: "registry", id: registryRelay.id }
      : { kind: "registry_code", code: registryRelay.tokenId };
  } else {
    locator = { kind: "inline", relay };
  }
  return { relay, relayUrl, locator };
}

function validateRelay(relay: EtcatRelay): void {
  if (relay.id.length === 0) {
    throw new Error("etcat relay ID must not be empty");
  }
  if (relay.endpoints.length === 0 || relay.endpoints.length > 255) {
    throw new Error("etcat relay must have between 1 and 255 endpoints");
  }
  for (const endpoint of relay.endpoints) {
    const bytes = new TextEncoder().encode(endpoint);
    if (bytes.byteLength === 0 || bytes.byteLength > 65_535) {
      throw new Error("etcat relay endpoint must contain between 1 and 65535 UTF-8 bytes");
    }
    try {
      new URL(endpoint);
    } catch {
      throw new Error(`etcat relay endpoint ${JSON.stringify(endpoint)} is not a valid URL`);
    }
  }
  if (relay.publicKey !== undefined) {
    decodeFixedBase64(relay.publicKey, 32, "relay public key");
  }
}

function sameRelay(left: EtcatRelay, right: EtcatRelay): boolean {
  return left.id === right.id &&
    left.publicKey === right.publicKey &&
    left.tokenId === right.tokenId &&
    left.endpoints.length === right.endpoints.length &&
    left.endpoints.every((endpoint, index) => endpoint === right.endpoints[index]);
}

function selectGatewayPort(
  options: EtcatBrowserListenOptions,
  key: EtcatBrowserServerKey,
): number {
  const selected = options.gatewayPort ?? key.gatewayPort;
  if (selected !== undefined) {
    validatePort(selected, "gateway");
    return selected;
  }
  const random = secureRandomBytes(2);
  const value = new DataView(random.buffer, random.byteOffset, 2).getUint16(0, false);
  return FIRST_EPHEMERAL_PORT + (value % EPHEMERAL_PORT_COUNT);
}

function expiryFromTtl(ttlSeconds: number | undefined): number | undefined {
  if (ttlSeconds === undefined) {
    return undefined;
  }
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1) {
    throw new Error("etcat browser server TTL must be a positive integer of seconds");
  }
  const expiry = Math.floor(Date.now() / 1000) + ttlSeconds;
  if (!Number.isSafeInteger(expiry) || expiry > 0xffff_ffff) {
    throw new Error("etcat browser server TTL exceeds the connection-token range");
  }
  return expiry;
}

function validateOptions(options: EtcatBrowserListenOptions): void {
  if (typeof options.onConnection !== "function") {
    throw new Error("etcat browser server requires an onConnection callback");
  }
  validatePositiveInteger(
    options.maxConnections,
    "maximum concurrent connections",
  );
  validatePositiveInteger(
    options.handshakeTimeoutMilliseconds,
    "handshake timeout",
  );
  if (options.gatewayPort !== undefined) {
    validatePort(options.gatewayPort, "gateway");
  }
}

function validatePositiveInteger(value: number | undefined, name: string): void {
  if (value !== undefined && (!Number.isInteger(value) || value < 1)) {
    throw new Error(`etcat browser server ${name} must be a positive integer`);
  }
}

function validatePort(port: number, name: string): void {
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`etcat browser server ${name} port must be between 1 and 65535`);
  }
}

function encodeConnectionToken(
  fingerprint: Uint8Array,
  gatewayPort: number,
  expiresUnix: number | undefined,
  bearerSeed: Uint8Array,
  relay: RelayLocator,
): string {
  const relayKind = relay.kind === "registry_code"
    ? REGISTRY_CODE_RELAY
    : relay.kind === "registry"
      ? REGISTRY_RELAY
      : INLINE_RELAY;
  const flags = (relayKind << 2) |
    (expiresUnix === undefined ? 0 : TOKEN_EXPIRY_FLAG);
  const parts = [
    new Uint8Array([flags]),
    fingerprint,
    encodeU16(gatewayPort),
  ];
  if (expiresUnix !== undefined) {
    parts.push(encodeU32(expiresUnix));
  }
  parts.push(bearerSeed, encodeRelayLocator(relay));
  const encoded = encodeBase32Token(concatBytes(...parts));
  if (encoded.length > MAX_ENCODED_TOKEN_LENGTH) {
    throw new Error(
      `etcat connection token exceeds ${MAX_ENCODED_TOKEN_LENGTH} characters`,
    );
  }
  return encoded;
}

function encodeRelayLocator(relay: RelayLocator): Uint8Array {
  if (relay.kind === "registry_code") {
    if (!Number.isInteger(relay.code) || relay.code < 1 || relay.code > 65_535) {
      throw new Error("etcat relay token ID must be between 1 and 65535");
    }
    return encodeU16(relay.code);
  }
  if (relay.kind === "registry") {
    const id = new TextEncoder().encode(relay.id);
    if (id.byteLength === 0 || id.byteLength > 128) {
      throw new Error("etcat relay registry ID must contain between 1 and 128 UTF-8 bytes");
    }
    return concatBytes(new Uint8Array([id.byteLength]), id);
  }
  const parts: Uint8Array[] = [
    new Uint8Array([relay.relay.endpoints.length]),
  ];
  for (const endpoint of relay.relay.endpoints) {
    const encoded = new TextEncoder().encode(endpoint);
    parts.push(encodeU16(encoded.byteLength), encoded);
  }
  if (relay.relay.publicKey === undefined) {
    parts.push(new Uint8Array([0]));
  } else {
    parts.push(
      new Uint8Array([1]),
      decodeFixedBase64(relay.relay.publicKey, 32, "relay public key"),
    );
  }
  return concatBytes(...parts);
}

function encodeBase32Token(bytes: Uint8Array): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let accumulator = 0;
  let bits = 0;
  let payload = "";
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      payload += alphabet[(accumulator >>> bits) & 0x1f];
      accumulator &= (1 << bits) - 1;
    }
  }
  if (bits !== 0) {
    payload += alphabet[(accumulator << (5 - bits)) & 0x1f];
  }
  const compact = `${TOKEN_PREFIX}${payload}`;
  return compact.match(/.{1,63}/g)?.join(".") ?? compact;
}

interface DecodedGatewayRequest {
  version: number;
  nonce: CborValue[];
  destination: EtcatDestination;
  authenticator: Uint8Array;
}

function decodeGatewayRequest(bytes: Uint8Array): DecodedGatewayRequest {
  const request = requireCborMap(decodeCbor(bytes));
  requireExactFields(
    request,
    ["version", "nonce", "destination", "authenticator"],
    "gateway request",
  );
  if (request.version !== 2) {
    throw new Error(`unsupported gateway protocol version ${String(request.version)}`);
  }
  const nonce = requireByteArray(request.nonce, "gateway nonce", 32);
  const destination = decodeDestination(request.destination);
  if (!(request.authenticator instanceof Uint8Array)) {
    throw new Error("gateway request authenticator is not bytes");
  }
  return {
    version: 2,
    nonce,
    destination,
    authenticator: request.authenticator,
  };
}

function decodeDestination(value: CborValue | undefined): EtcatDestination {
  const destination = requireCborMap(value as CborValue);
  if (destination.kind === "ping") {
    requireExactFields(destination, ["kind"], "ping destination");
    return { kind: "ping" };
  }
  if (destination.kind === "server_port") {
    requireExactFields(destination, ["kind", "port"], "server-port destination");
    return {
      kind: "server_port",
      port: requireU16(destination.port, "server destination port"),
    };
  }
  if (destination.kind === "exit_node") {
    requireExactFields(destination, ["kind", "host", "port"], "exit-node destination");
    if (typeof destination.host !== "string") {
      throw new Error("exit-node destination host is not text");
    }
    return {
      kind: "exit_node",
      host: destination.host,
      port: requireU16(destination.port, "exit-node destination port"),
    };
  }
  throw new Error("unsupported etcat destination");
}

function requireExactFields(
  value: { [key: string]: CborValue },
  expected: readonly string[],
  name: string,
): void {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (
    actual.length !== sortedExpected.length ||
    actual.some((field, index) => field !== sortedExpected[index])
  ) {
    throw new Error(`${name} contains unknown or missing fields`);
  }
}

function requireByteArray(
  value: CborValue | undefined,
  name: string,
  length: number,
): CborValue[] {
  if (
    !Array.isArray(value) ||
    value.length !== length ||
    value.some((byte) =>
      typeof byte !== "number" ||
      !Number.isInteger(byte) ||
      byte < 0 ||
      byte > 255
    )
  ) {
    throw new Error(`${name} must be an array of ${length} bytes`);
  }
  return value;
}

function requireU16(value: CborValue | undefined, name: string): number {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < 0 ||
    value > 65_535
  ) {
    throw new Error(`${name} is not an unsigned 16-bit integer`);
  }
  return value;
}

async function authorizationRejection(
  authorize: EtcatBrowserListenOptions["authorize"],
  destination: EtcatDestination,
): Promise<string | undefined> {
  if (destination.kind === "ping") {
    return undefined;
  }
  if (authorize === undefined) {
    return destination.kind === "server_port" && destination.port === 1
      ? undefined
      : "destination is not served by this browser receiver";
  }
  try {
    const decision = await authorize(destination);
    if (decision === true) {
      return undefined;
    }
    return typeof decision === "string"
      ? decision
      : "destination rejected by service policy";
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

async function writeGatewayResponse(
  stream: EasyTierTcpStream,
  networkName: string,
  requestBytes: Uint8Array,
  key: LoadedServerKey,
  rejection: string | undefined,
): Promise<void> {
  const accepted = rejection === undefined;
  const message = rejection ?? "";
  const transcript = await gatewayTranscript(
    networkName,
    requestBytes,
    key.signingPublicBytes,
    accepted,
    message,
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign("Ed25519", key.signingPrivateKey, transcript),
  );
  await writeFrame(
    stream,
    encodeCborMap([
      ["accepted", accepted],
      ["message", message],
      ["public_key", encodeBase64(key.signingPublicBytes)],
      ["signature", encodeBase64(signature)],
    ]),
  );
}

function decodeCanonicalBase64(value: string, name: string): OwnedBytes {
  let decoded: OwnedBytes;
  try {
    decoded = decodeBase64(value);
  } catch {
    throw new Error(`etcat browser ${name} is not valid base64`);
  }
  if (encodeBase64(decoded) !== value) {
    throw new Error(`etcat browser ${name} is not canonical base64`);
  }
  return decoded;
}

function decodeFixedBase64(
  value: string,
  length: number,
  name: string,
): OwnedBytes {
  const decoded = decodeCanonicalBase64(value, name);
  if (decoded.byteLength !== length) {
    throw new Error(`etcat browser ${name} must contain ${length} bytes`);
  }
  return decoded;
}

function encodeU16(value: number): OwnedBytes {
  const bytes = new Uint8Array(2);
  new DataView(bytes.buffer).setUint16(0, value, false);
  return bytes;
}

function secureRandomBytes(length: number): OwnedBytes {
  return crypto.getRandomValues(new Uint8Array(length));
}

async function withTimeout<T>(
  operation: Promise<T>,
  milliseconds: number,
  message: string,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(message)), milliseconds);
      }),
    ]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

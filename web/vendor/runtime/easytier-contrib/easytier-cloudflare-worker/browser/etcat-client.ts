import { EasyTierRuntime } from "../src/core-runtime";
import type { EasyTierTcpStream } from "../src/data-plane";
import type { EasyTierCoreEvent } from "../src/websocket-host";
import { BUILTIN_ETCAT_RELAY_REGISTRY } from "./etcat-relays.generated";

export { BUILTIN_ETCAT_RELAY_REGISTRY };

const TOKEN_PREFIX = "etc2";
const TOKEN_EXPIRY_FLAG = 0x10;
const TOKEN_CREDENTIAL_MASK = 0x03;
const TOKEN_RELAY_MASK = 0x0c;
const TOKEN_RELAY_SHIFT = 2;
const REGISTRY_CODE_RELAY = 0;
const REGISTRY_RELAY = 1;
const INLINE_RELAY = 2;
const MAX_GATEWAY_FRAME = 4096;
const ROUTE_RETRY_MILLISECONDS = 100;
export const GATEWAY_SIGNATURE_DOMAIN = new TextEncoder().encode(
  "etcat-gateway-v2\0",
);
export const CLIENT_AUTH_DOMAIN = new TextEncoder().encode(
  "etcat-client-auth-v2\0",
);
const CREDENTIAL_KDF_SALT = new TextEncoder().encode("etcat credential v2");
const EASYTIER_CREDENTIAL_INFO = new TextEncoder().encode(
  "easytier x25519 private key",
);
export const GATEWAY_AUTHENTICATION_INFO = new TextEncoder().encode(
  "gateway hmac-sha256 key",
);

export type OwnedBytes = Uint8Array<ArrayBuffer>;

export function ownedBytes(value: Uint8Array): OwnedBytes {
  return new Uint8Array(value);
}

interface ParsedEtcatToken {
  fingerprint: Uint8Array;
  gatewayPort: number;
  expiresUnix: number | undefined;
  credentialSeed: Uint8Array;
  relay: ParsedRelayLocator;
}

interface ParsedRelay {
  endpoints: readonly string[];
  publicKey: string | undefined;
}

type ParsedRelayLocator =
  | { kind: "registry_code"; code: number }
  | { kind: "registry"; id: string }
  | { kind: "inline"; relay: ParsedRelay };

export type EtcatDestination =
  | { kind: "ping" }
  | { kind: "server_port"; port: number }
  | { kind: "exit_node"; host: string; port: number };

export interface EtcatRelay {
  id: string;
  endpoints: readonly string[];
  publicKey?: string;
  tokenId?: number;
}

export interface EtcatRelayRegistry {
  version: 1;
  relays: readonly EtcatRelay[];
}

export interface EtcatBrowserOptions {
  relayRegistry?: EtcatRelayRegistry;
}

export interface EtcatBrowserConnection {
  runtime: EasyTierRuntime;
  networkName: string;
  gatewayIpv4: string;
  gatewayPort: number;
  fingerprint: Uint8Array;
  authenticationKey: Uint8Array;
}

export async function connectEtcatBrowser(
  module: WebAssembly.Module,
  encodedToken: string,
  onEvent?: (event: EasyTierCoreEvent) => void,
  options: EtcatBrowserOptions = {},
): Promise<EtcatBrowserConnection> {
  const token = parseEtcatToken(encodedToken);
  if (
    token.expiresUnix !== undefined &&
    Math.floor(Date.now() / 1000) >= token.expiresUnix
  ) {
    throw new Error("etcat connection token has expired");
  }
  const networkName = `etcat-${hex(token.fingerprint)}`;
  const networkDigest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(networkName)),
  );
  const credentialKey = await deriveCredentialKey(
    token.credentialSeed,
    EASYTIER_CREDENTIAL_INFO,
  );
  const authenticationKey = await deriveCredentialKey(
    token.credentialSeed,
    GATEWAY_AUTHENTICATION_INFO,
  );
  const credentialSecret = encodeBase64(credentialKey);
  const instanceDigest = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(credentialSecret),
    ),
  );
  const clientIpv4 = `10.${networkDigest[0]}.${networkDigest[1]}.2`;
  const gatewayIpv4 = `100.${64 + (networkDigest[0]! % 64)}.${networkDigest[1]}.${networkDigest[2]}`;
  const relay = resolveBrowserRelay(
    token.relay,
    options.relayRegistry ?? BUILTIN_ETCAT_RELAY_REGISTRY,
  );
  const relayUrl = selectBrowserRelay(
    relay.endpoints,
    currentPageProtocol(),
  );
  const peerPublicKey = relay.publicKey;
  const config = `
instance_id = "${formatUuid(instanceDigest.subarray(0, 16))}"
instance_name = "etcat-browser"
ipv4 = "${clientIpv4}/24"
listeners = []

[network_identity]
network_name = "${escapeToml(networkName)}"

[secure_mode]
enabled = true
local_private_key = "${escapeToml(credentialSecret)}"

[[peer]]
uri = "${escapeToml(relayUrl)}"${
    peerPublicKey === undefined
      ? ""
      : `\npeer_public_key = "${escapeToml(peerPublicKey)}"`
  }

[flags]
no_tun = true
use_smoltcp = true
disable_p2p = true
enable_encryption = true
bind_device = false
`;
  const runtime = new EasyTierRuntime(
    module,
    config,
    (url) => new WebSocket(url),
    onEvent,
  );
  try {
    await runtime.ready;
  } catch (error) {
    await runtime.stop().catch(() => undefined);
    throw error;
  }
  return {
    runtime,
    networkName,
    gatewayIpv4,
    gatewayPort: token.gatewayPort,
    fingerprint: token.fingerprint,
    authenticationKey,
  };
}

export async function openEtcatStream(
  connection: EtcatBrowserConnection,
  destination: EtcatDestination,
  timeoutMilliseconds = 5000,
): Promise<EasyTierTcpStream> {
  validateDestination(destination);
  if (!Number.isSafeInteger(timeoutMilliseconds) || timeoutMilliseconds < 0) {
    throw new Error("etcat connection timeout must be a non-negative safe integer");
  }
  const startedAt = Date.now();
  let stream: EasyTierTcpStream;
  for (;;) {
    const remaining = remainingTimeout(startedAt, timeoutMilliseconds);
    try {
      stream = await connection.runtime.connectTcp(
        connection.gatewayIpv4,
        connection.gatewayPort,
        remaining,
      );
      break;
    } catch (error) {
      if (!isMissingOverlayRoute(error) || remaining === 0) {
        throw error;
      }
      await new Promise((resolve) =>
        setTimeout(resolve, Math.min(ROUTE_RETRY_MILLISECONDS, remaining))
      );
    }
  }
  try {
    await withTimeout(
      gatewayHandshake(
        stream,
        connection.networkName,
        destination,
        connection.fingerprint,
        connection.authenticationKey,
      ),
      remainingTimeout(startedAt, timeoutMilliseconds),
      "etcat gateway handshake timed out",
    );
    return stream;
  } catch (error) {
    await stream.close().catch(() => undefined);
    throw error;
  }
}

function isMissingOverlayRoute(error: unknown): boolean {
  return error instanceof Error && error.message.includes("NoOverlayRoute");
}

function remainingTimeout(startedAt: number, timeoutMilliseconds: number): number {
  return Math.max(0, timeoutMilliseconds - (Date.now() - startedAt));
}

async function withTimeout<T>(
  operation: Promise<T>,
  timeoutMilliseconds: number,
  message: string,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(message)), timeoutMilliseconds);
      }),
    ]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

function parseEtcatToken(encoded: string): ParsedEtcatToken {
  if (encoded.length > 16 * 1024) {
    throw new Error("etcat connection token is too long");
  }
  const labels = encoded.split(".");
  if (
    labels.some((label) => label.length === 0 || label.length > 63) ||
    !/^[a-z0-9.]+$/.test(encoded)
  ) {
    throw new Error("invalid etcat connection token hostname");
  }
  const compact = labels.join("");
  if (!compact.startsWith(TOKEN_PREFIX)) {
    throw new Error("etcat connection token must start with 'etc2'");
  }
  const reader = new ByteReader(decodeBase32(compact.slice(TOKEN_PREFIX.length)));
  const flags = reader.u8();
  if ((flags & 0xe0) !== 0) {
    throw new Error("etcat connection token has unsupported flags");
  }
  const credentialKind = flags & TOKEN_CREDENTIAL_MASK;
  if (credentialKind === 1) {
    throw new Error(
      "browser etcat does not support sealed HPKE credentials; use a bearer token",
    );
  }
  if (credentialKind !== 0) {
    throw new Error("etcat connection token has unsupported credential type");
  }
  const relayKind = (flags & TOKEN_RELAY_MASK) >> TOKEN_RELAY_SHIFT;
  if (relayKind > INLINE_RELAY) {
    throw new Error("etcat connection token has unsupported relay type");
  }
  const fingerprint = reader.bytes(16);
  const gatewayPort = reader.u16();
  if (gatewayPort === 0) {
    throw new Error("etcat gateway port must be non-zero");
  }
  const expiresUnix = (flags & TOKEN_EXPIRY_FLAG) === 0 ? undefined : reader.u32();
  const credentialSeed = reader.bytes(16);
  const relay = parseRelayLocator(reader, relayKind);
  if (!reader.done()) {
    throw new Error("etcat connection token contains trailing data");
  }
  return {
    fingerprint,
    gatewayPort,
    expiresUnix,
    credentialSeed,
    relay,
  };
}

function parseRelayLocator(
  reader: ByteReader,
  relayKind: number,
): ParsedRelayLocator {
  if (relayKind === REGISTRY_CODE_RELAY) {
    const code = reader.u16();
    if (code === 0) {
      throw new Error("etcat relay token ID must be non-zero");
    }
    return { kind: "registry_code", code };
  }
  if (relayKind === REGISTRY_RELAY) {
    const idBytes = reader.bytes(reader.u8());
    if (idBytes.byteLength === 0 || idBytes.byteLength > 128) {
      throw new Error("invalid etcat relay registry ID");
    }
    const id = decodeUtf8(idBytes, "relay registry ID");
    return { kind: "registry", id };
  }
  const relayCount = reader.u8();
  if (relayCount === 0) {
    throw new Error("embedded etcat relay has no endpoints");
  }
  const relayUrls: string[] = [];
  for (let index = 0; index < relayCount; index += 1) {
    relayUrls.push(
      decodeUtf8(reader.bytes(reader.u16()), "embedded relay endpoint"),
    );
  }
  const publicKeyFlag = reader.u8();
  const relayPublicKey =
    publicKeyFlag === 0
      ? undefined
      : publicKeyFlag === 1
        ? encodeBase64(reader.bytes(32))
        : (() => {
            throw new Error("embedded etcat relay has invalid public-key flag");
          })();
  return {
    kind: "inline",
    relay: {
      endpoints: relayUrls,
      publicKey: relayPublicKey,
    },
  };
}

function decodeUtf8(value: Uint8Array, name: string): string {
  try {
    return new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: false,
    }).decode(value);
  } catch {
    throw new Error(`${name} is not UTF-8`);
  }
}

export async function deriveCredentialKey(
  seed: Uint8Array,
  info: Uint8Array,
): Promise<OwnedBytes> {
  const key = await crypto.subtle.importKey("raw", ownedBytes(seed), "HKDF", false, [
    "deriveBits",
  ]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: CREDENTIAL_KDF_SALT,
        info: ownedBytes(info),
      },
      key,
      256,
    ),
  );
}

async function gatewayHandshake(
  stream: EasyTierTcpStream,
  networkName: string,
  destination: EtcatDestination,
  expectedFingerprint: Uint8Array,
  authenticationKey: Uint8Array,
): Promise<void> {
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const canonicalDestination = canonicalEtcatDestination(destination);
  const authenticationBytes = encodeCborMap([
    ["domain", Array.from(CLIENT_AUTH_DOMAIN)],
    ["network_name", networkName],
    ["version", 2],
    ["nonce", Array.from(nonce)],
    ["destination", canonicalDestination],
  ]);
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    ownedBytes(authenticationKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const authenticator = new Uint8Array(
    await crypto.subtle.sign("HMAC", hmacKey, authenticationBytes),
  );
  const request = encodeCborMap([
    ["version", 2],
    ["nonce", Array.from(nonce)],
    ["destination", canonicalDestination],
    ["authenticator", authenticator],
  ]);
  await writeFrame(stream, request);
  const response = requireCborMap(decodeCbor(await readFrame(stream)));
  const accepted = requireBoolean(response.accepted, "accepted");
  const message = requireString(response.message, "message");
  const publicKey = decodeBase64(
    requireString(response.public_key, "public_key"),
  );
  const signature = decodeBase64(
    requireString(response.signature, "signature"),
  );
  if (publicKey.byteLength !== 32 || signature.byteLength !== 64) {
    throw new Error("etcat gateway returned invalid identity material");
  }
  const fingerprint = new Uint8Array(
    await crypto.subtle.digest("SHA-256", ownedBytes(publicKey)),
  ).subarray(0, 16);
  if (!equalBytes(fingerprint, expectedFingerprint)) {
    throw new Error("etcat gateway identity does not match the connection token");
  }
  const transcript = await gatewayTranscript(
    networkName,
    request,
    publicKey,
    accepted,
    message,
  );
  const verifyingKey = await crypto.subtle.importKey(
    "raw",
    ownedBytes(publicKey),
    "Ed25519",
    false,
    ["verify"],
  );
  if (
    !(await crypto.subtle.verify(
      "Ed25519",
      verifyingKey,
      ownedBytes(signature),
      transcript,
    ))
  ) {
    throw new Error("etcat gateway identity does not match the connection token");
  }
  if (!accepted) {
    throw new Error(`etcat gateway rejected the connection: ${message}`);
  }
}

export async function gatewayTranscript(
  networkName: string,
  request: Uint8Array,
  publicKey: Uint8Array,
  accepted: boolean,
  message: string,
): Promise<OwnedBytes> {
  const network = new TextEncoder().encode(networkName);
  const encodedMessage = new TextEncoder().encode(message);
  const transcript = concatBytes(
    GATEWAY_SIGNATURE_DOMAIN,
    encodeU32(network.byteLength),
    network,
    encodeU32(request.byteLength),
    request,
    publicKey,
    new Uint8Array([accepted ? 1 : 0]),
    encodeU32(encodedMessage.byteLength),
    encodedMessage,
  );
  return new Uint8Array(await crypto.subtle.digest("SHA-256", transcript));
}

export async function writeFrame(
  stream: EasyTierTcpStream,
  payload: Uint8Array,
): Promise<void> {
  if (payload.byteLength > MAX_GATEWAY_FRAME) {
    throw new Error("etcat gateway frame is too large");
  }
  await writeAll(
    stream,
    concatBytes(encodeU32(payload.byteLength), payload),
  );
}

export async function readFrame(stream: EasyTierTcpStream): Promise<Uint8Array> {
  const reader = new TcpReader(stream);
  const lengthBytes = await reader.readExact(4);
  const length = new DataView(
    lengthBytes.buffer,
    lengthBytes.byteOffset,
    lengthBytes.byteLength,
  ).getUint32(0, false);
  if (length > MAX_GATEWAY_FRAME) {
    throw new Error("etcat gateway frame is too large");
  }
  return reader.readExact(length);
}

class TcpReader {
  private buffered: Uint8Array = new Uint8Array();

  constructor(private readonly stream: EasyTierTcpStream) {}

  async readExact(length: number): Promise<Uint8Array> {
    while (this.buffered.byteLength < length) {
      const next = await this.stream.read(length - this.buffered.byteLength);
      if (next.data.byteLength !== 0) {
        this.buffered = concatBytes(this.buffered, next.data);
      }
      if (next.eof && this.buffered.byteLength < length) {
        throw new Error("etcat gateway closed an incomplete frame");
      }
    }
    const result = this.buffered.slice(0, length);
    this.buffered = this.buffered.slice(length);
    return result;
  }
}

async function writeAll(
  stream: EasyTierTcpStream,
  data: Uint8Array,
): Promise<void> {
  let offset = 0;
  while (offset < data.byteLength) {
    const written = await stream.write(data.subarray(offset));
    if (written <= 0 || written > data.byteLength - offset) {
      throw new Error(`etcat stream returned invalid write length ${written}`);
    }
    offset += written;
  }
}

export type CborValue =
  | boolean
  | number
  | string
  | Uint8Array
  | CborValue[]
  | { [key: string]: CborValue };

export function encodeCborMap(
  entries: Array<[string, CborValue]>,
): OwnedBytes {
  return encodeCbor(Object.fromEntries(entries) as { [key: string]: CborValue });
}

function encodeCbor(value: CborValue): OwnedBytes {
  const output: number[] = [];
  encodeCborValue(output, value);
  return new Uint8Array(output);
}

function encodeCborValue(output: number[], value: CborValue): void {
  if (typeof value === "boolean") {
    output.push(value ? 0xf5 : 0xf4);
  } else if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error("CBOR only supports non-negative safe integers here");
    }
    encodeCborLength(output, 0, value);
  } else if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    encodeCborLength(output, 3, bytes.byteLength);
    output.push(...bytes);
  } else if (value instanceof Uint8Array) {
    encodeCborLength(output, 2, value.byteLength);
    output.push(...value);
  } else if (Array.isArray(value)) {
    encodeCborLength(output, 4, value.length);
    for (const item of value) {
      encodeCborValue(output, item);
    }
  } else {
    const entries = Object.entries(value);
    encodeCborLength(output, 5, entries.length);
    for (const [key, item] of entries) {
      encodeCborValue(output, key);
      encodeCborValue(output, item);
    }
  }
}

function encodeCborLength(
  output: number[],
  major: number,
  value: number,
): void {
  const prefix = major << 5;
  if (value < 24) {
    output.push(prefix | value);
  } else if (value <= 0xff) {
    output.push(prefix | 24, value);
  } else if (value <= 0xffff) {
    output.push(prefix | 25, value >>> 8, value & 0xff);
  } else if (value <= 0xffff_ffff) {
    output.push(prefix | 26, ...encodeU32(value));
  } else {
    throw new Error("CBOR integer is too large");
  }
}

export function decodeCbor(bytes: Uint8Array): CborValue {
  const reader = new CborReader(bytes);
  const value = reader.value();
  if (!reader.done()) {
    throw new Error("CBOR value contains trailing data");
  }
  return value;
}

class ByteReader {
  private offset = 0;

  constructor(private readonly input: Uint8Array) {}

  u8(): number {
    return this.bytes(1)[0]!;
  }

  u16(): number {
    const bytes = this.bytes(2);
    return new DataView(bytes.buffer, bytes.byteOffset, 2).getUint16(0, false);
  }

  u32(): number {
    const bytes = this.bytes(4);
    return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false);
  }

  bytes(length: number): Uint8Array {
    if (length < 0 || this.offset + length > this.input.byteLength) {
      throw new Error("encoded value is truncated");
    }
    const result = this.input.slice(this.offset, this.offset + length);
    this.offset += length;
    return result;
  }

  done(): boolean {
    return this.offset === this.input.byteLength;
  }
}

class CborReader extends ByteReader {
  value(): CborValue {
    const initial = this.u8();
    const major = initial >>> 5;
    const additional = initial & 0x1f;
    if (major === 7 && (additional === 20 || additional === 21)) {
      return additional === 21;
    }
    const length = this.cborLength(additional);
    if (major === 0) {
      return length;
    }
    if (major === 2) {
      return this.bytes(length);
    }
    if (major === 3) {
      return new TextDecoder("utf-8", {
        fatal: true,
        ignoreBOM: false,
      }).decode(this.bytes(length));
    }
    if (major === 4) {
      return Array.from({ length }, () => this.value());
    }
    if (major === 5) {
      const result: { [key: string]: CborValue } = Object.create(null) as {
        [key: string]: CborValue;
      };
      for (let index = 0; index < length; index += 1) {
        const key = this.value();
        if (typeof key !== "string") {
          throw new Error("CBOR map key is not text");
        }
        if (Object.hasOwn(result, key)) {
          throw new Error(`CBOR map contains duplicate key ${JSON.stringify(key)}`);
        }
        result[key] = this.value();
      }
      return result;
    }
    throw new Error(`unsupported CBOR major type ${major}`);
  }

  private cborLength(additional: number): number {
    if (additional < 24) {
      return additional;
    }
    if (additional === 24) {
      return this.u8();
    }
    if (additional === 25) {
      return this.u16();
    }
    if (additional === 26) {
      return this.u32();
    }
    throw new Error("unsupported CBOR length encoding");
  }
}

function decodeBase32(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const output: number[] = [];
  let accumulator = 0;
  let bits = 0;
  for (const character of value.toUpperCase()) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) {
      throw new Error("etcat connection token is not valid base32");
    }
    accumulator = (accumulator << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((accumulator >>> bits) & 0xff);
      accumulator &= (1 << bits) - 1;
    }
  }
  if (bits !== 0 && accumulator !== 0) {
    throw new Error("etcat connection token has invalid base32 padding");
  }
  return new Uint8Array(output);
}

export function decodeBase64(value: string): OwnedBytes {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function encodeBase64(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function encodeU32(value: number): OwnedBytes {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

export function concatBytes(...parts: Uint8Array[]): OwnedBytes {
  const output = new Uint8Array(
    parts.reduce((total, part) => total + part.byteLength, 0),
  );
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function resolveBrowserRelay(
  locator: ParsedRelayLocator,
  registry: EtcatRelayRegistry,
): ParsedRelay {
  if (locator.kind === "inline") {
    return locator.relay;
  }
  validateRelayRegistry(registry);
  const relay = locator.kind === "registry"
    ? registry.relays.find((candidate) => candidate.id === locator.id)
    : registry.relays.find((candidate) => candidate.tokenId === locator.code);
  if (relay === undefined) {
    const reference = locator.kind === "registry"
      ? `relay ${JSON.stringify(locator.id)}`
      : `relay token ID ${locator.code}`;
    throw new Error(`${reference} is not in the browser relay registry`);
  }
  if (relay.publicKey !== undefined) {
    let decoded: Uint8Array;
    try {
      decoded = decodeBase64(relay.publicKey);
    } catch {
      throw new Error(`relay ${JSON.stringify(relay.id)} has an invalid public key`);
    }
    if (decoded.byteLength !== 32) {
      throw new Error(
        `relay ${JSON.stringify(relay.id)} public key must contain 32 bytes`,
      );
    }
  }
  return {
    endpoints: relay.endpoints,
    publicKey: relay.publicKey,
  };
}

export function validateRelayRegistry(registry: EtcatRelayRegistry): void {
  if (registry.version !== 1) {
    throw new Error(`unsupported browser relay registry version ${String(registry.version)}`);
  }
  const ids = new Set<string>();
  const tokenIds = new Set<number>();
  for (const relay of registry.relays) {
    if (relay.id.length === 0 || ids.has(relay.id)) {
      throw new Error("browser relay IDs must be non-empty and unique");
    }
    ids.add(relay.id);
    if (relay.endpoints.length === 0) {
      throw new Error(`relay ${JSON.stringify(relay.id)} has no endpoints`);
    }
    if (relay.tokenId !== undefined) {
      if (
        !Number.isInteger(relay.tokenId) ||
        relay.tokenId < 1 ||
        relay.tokenId > 65_535 ||
        tokenIds.has(relay.tokenId)
      ) {
        throw new Error(
          "browser relay token IDs must be unique integers between 1 and 65535",
        );
      }
      tokenIds.add(relay.tokenId);
    }
  }
}

export function selectBrowserRelay(
  relays: readonly string[],
  pageProtocol: string | undefined,
): string {
  const compatible = relays.filter((relay) => {
    try {
      const protocol = new URL(relay).protocol;
      return protocol === "ws:" || protocol === "wss:";
    } catch {
      return false;
    }
  });
  const secure = compatible.find((candidate) => new URL(candidate).protocol === "wss:");
  if (secure !== undefined) {
    return secure;
  }
  const relay = compatible[0];
  if (relay === undefined) {
    throw new Error(
      "etcat relay has no browser-compatible ws:// or wss:// endpoint",
    );
  }
  if (pageProtocol === "https:") {
    throw new Error(
      "etcat cannot use an insecure ws:// relay from an HTTPS page; configure a wss:// endpoint",
    );
  }
  return relay;
}

export function currentPageProtocol(): string | undefined {
  const global = globalThis as typeof globalThis & {
    location?: { protocol?: unknown };
  };
  return typeof global.location?.protocol === "string"
    ? global.location.protocol
    : undefined;
}

function validateDestination(destination: EtcatDestination): void {
  if (
    destination.kind !== "ping" &&
    destination.kind !== "server_port" &&
    destination.kind !== "exit_node"
  ) {
    throw new Error("unsupported etcat destination");
  }
  if (
    "port" in destination &&
    (!Number.isInteger(destination.port) ||
      destination.port < 1 ||
      destination.port > 65_535)
  ) {
    throw new Error("etcat destination port must be between 1 and 65535");
  }
  if (destination.kind === "exit_node" && destination.host.length === 0) {
    throw new Error("etcat exit-node destination host is empty");
  }
}

export function canonicalEtcatDestination(
  destination: EtcatDestination,
): EtcatDestination {
  switch (destination.kind) {
    case "ping":
      return { kind: "ping" };
    case "server_port":
      return { kind: "server_port", port: destination.port };
    case "exit_node":
      return {
        kind: "exit_node",
        host: destination.host,
        port: destination.port,
      };
  }
}

export function requireCborMap(
  value: CborValue,
): { [key: string]: CborValue } {
  if (
    typeof value !== "object" ||
    value instanceof Uint8Array ||
    Array.isArray(value)
  ) {
    throw new Error("etcat gateway response is not a CBOR map");
  }
  return value;
}

export function requireString(
  value: CborValue | undefined,
  name: string,
): string {
  if (typeof value !== "string") {
    throw new Error(`etcat gateway response field ${name} is not text`);
  }
  return value;
}

export function requireBoolean(
  value: CborValue | undefined,
  name: string,
): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`etcat gateway response field ${name} is not boolean`);
  }
  return value;
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

export function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function formatUuid(value: Uint8Array): string {
  const encoded = hex(value);
  return [
    encoded.slice(0, 8),
    encoded.slice(8, 12),
    encoded.slice(12, 16),
    encoded.slice(16, 20),
    encoded.slice(20),
  ].join("-");
}

export function escapeToml(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

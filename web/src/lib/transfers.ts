import { reactive } from "vue";
import {
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
} from "./runtime";
import { relayFromSettings } from "./runtime";
import { settings } from "./settings";
import { recordError, testState } from "./testhooks";
import { requireWasmModule } from "./wasm";

const RELAY_CONNECT_TIMEOUT_MS = 30_000;
const STREAM_OPEN_TIMEOUT_MS = 30_000;
const STREAM_OPEN_ATTEMPT_MS = 5_000;

// Port-2 file transfers carry a versioned metadata frame; see
// receive_named_file in src/app.rs. The version lives in the last two magic
// digits, and JSON header keys are additive, so implementations never break
// each other.
const FILE_FRAME_MAGIC = new TextEncoder().encode("ETCATF01");
const FILE_META_PORT = 2;

export type TransferStatus =
  | "connecting"
  | "transferring"
  | "confirming"
  | "done"
  | "failed";

export interface Transfer {
  id: number;
  direction: "send" | "receive";
  kind: "file" | "text" | "stream";
  /** File name for sends; receives have no metadata in the protocol. */
  name: string | null;
  /** Total bytes for sends; unknown (null) for receives. */
  size: number | null;
  bytes: number;
  startedAt: number;
  status: TransferStatus;
  error: string | null;
  /** Decoded text of a completed text payload (either direction). */
  receivedText: string | null;
  /** Blob URL of a completed received file, buffered in memory. */
  downloadUrl: string | null;
  /** Re-runs a failed send with the original payload. */
  retry: (() => void) | null;
  /** Buffered payload of a completed received file, kept for saving. */
  blob: Blob | null;
  /** MIME from the metadata frame or magic-byte sniffing, when known. */
  mime: string | null;
}

export type ListenerStatus =
  | { kind: "idle" }
  | { kind: "starting" }
  | { kind: "listening"; token: string; relayReady: boolean }
  | { kind: "failed"; message: string };

interface TransferStore {
  listener: ListenerStatus;
  transfers: Transfer[];
}

export const store = reactive<TransferStore>({
  listener: { kind: "idle" },
  transfers: [],
});

let nextTransferId = 1;
let server: EtcatBrowserServer | undefined;
let sendQueue: Promise<void> = Promise.resolve();

function addTransfer(
  fields: Pick<Transfer, "direction" | "kind" | "name" | "size">,
): Transfer {
  const transfer = reactive<Transfer>({
    id: nextTransferId++,
    bytes: 0,
    startedAt: Date.now(),
    status: "connecting",
    error: null,
    receivedText: null,
    downloadUrl: null,
    retry: null,
    blob: null,
    mime: null,
    ...fields,
  });
  store.transfers.unshift(transfer);
  return transfer;
}

function relay() {
  return relayFromSettings(
    settings.relayUrl,
    settings.relayKey,
    window.location.protocol,
  );
}

function waitForRelayEvent(): {
  connected: Promise<void>;
  onEvent: (event: EasyTierCoreEvent) => void;
} {
  let notify!: () => void;
  let reject!: (error: Error) => void;
  const connected = new Promise<void>((resolve, rejectPromise) => {
    notify = resolve;
    reject = rejectPromise;
  });
  return {
    connected,
    onEvent: (event) => {
      if (event.kind === "peer_added") {
        notify();
      } else if (event.kind === "connect_error") {
        reject(new Error(`Relay connection failed: ${event.message}`));
      }
    },
  };
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
    clearTimeout(timer);
  }
}

export async function startListener(sinkHash: boolean): Promise<void> {
  if (store.listener.kind === "starting" || store.listener.kind === "listening") {
    return;
  }
  store.listener = { kind: "starting" };
  try {
    const persist = settings.persistListenerKey;
    const key = persist
      ? loadPersistentServerKey(window.localStorage)
      : undefined;
    let relayReady = false;
    let relayErrorReported = false;
    const nextServer = await etcatListen(requireWasmModule(), {
      relay: relay(),
      fullAddress: true,
      key,
      authorize: (destination) =>
        destination.kind === "server_port" &&
        (destination.port === 1 || destination.port === FILE_META_PORT)
          ? true
          : "the browser transfer listener only accepts server ports 1 and 2",
      onConnection: (connection) => handleIncoming(connection, sinkHash),
      onError: (error) => {
        recordError(error);
      },
      onEvent: (event) => {
        if (event.kind === "peer_added") {
          relayReady = true;
          if (store.listener.kind === "listening") {
            store.listener.relayReady = true;
          }
        } else if (event.kind === "connect_error" && !relayErrorReported) {
          // The connector retries; report only the first failure.
          relayErrorReported = true;
          recordError(new Error(`Relay connection failed: ${event.message}`));
        }
      },
    });
    if (persist) {
      try {
        storePersistentServerKey(window.localStorage, nextServer.key);
      } catch (error) {
        await nextServer.close();
        throw error;
      }
    }
    server = nextServer;
    testState.listenToken = nextServer.token;
    store.listener = {
      kind: "listening",
      token: nextServer.token,
      relayReady,
    };
  } catch (error) {
    store.listener = { kind: "failed", message: recordError(error) };
  }
}

export async function stopListener(): Promise<void> {
  const current = server;
  server = undefined;
  store.listener = { kind: "idle" };
  // Closing the server closes every in-flight incoming stream, which fails
  // those transfers out of the drain loop on its own.
  await current?.close().catch(() => undefined);
}

export function closeListenerOnPageHide(): void {
  window.addEventListener("pagehide", () => {
    void server?.close();
  });
}

/** Accepts a bare etc2 token or a pasted share link carrying ?token=. */
function normalizeToken(raw: string): string {
  const value = raw.trim();
  if (value.startsWith("etc2")) return value;
  try {
    const url = new URL(value);
    const token = url.searchParams.get("token");
    if (token !== null && token.startsWith("etc2")) return token;
  } catch {
    // Not a URL; fall through with the raw value.
  }
  return value;
}

export function enqueueSend(
  name: string | null,
  kind: "file" | "text",
  size: number,
  mime: string | null,
  reader: (offset: number, length: number) => Promise<Uint8Array>,
): Promise<void> {
  // Capture the token now: the queued payload must go to the receiver chosen
  // at submit time, not to whatever the input holds when the queue drains.
  const token = normalizeToken(pendingSend.token);
  // Serialize sends: one connection at a time keeps status readable and
  // avoids competing relay sessions.
  const run = sendQueue.then(() => sendPayload(token, name, kind, size, mime, reader));
  sendQueue = run.catch(() => undefined);
  return run;
}

async function sendPayload(
  token: string,
  name: string | null,
  kind: "file" | "text",
  size: number,
  mime: string | null,
  reader: (offset: number, length: number) => Promise<Uint8Array>,
): Promise<void> {
  const transfer = addTransfer({ direction: "send", kind, name, size });
  transfer.mime = mime;
  if (token.length === 0) {
    transfer.status = "failed";
    transfer.error = recordError(new Error("Paste the receiver's token or link first"));
    throw new Error(transfer.error);
  }
  transfer.retry = () => {
    transfer.status = "connecting";
    transfer.error = null;
    transfer.bytes = 0;
    transfer.startedAt = Date.now();
    const run = sendQueue.then(() => runSend(transfer, token, size, reader));
    sendQueue = run.catch(() => undefined);
    void run.catch(() => undefined);
  };
  await runSend(transfer, token, size, reader);
}

async function openStreamWithRetry(
  connection: EtcatBrowserConnection,
  port: number,
): Promise<EasyTierTcpStream> {
  // Route sync over the relay can outlive a single 5 s connect attempt; retry
  // transient connect failures until the overall budget is exhausted.
  const deadline = Date.now() + STREAM_OPEN_TIMEOUT_MS;
  for (;;) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new Error("Timed out opening a stream to the receiver");
    }
    try {
      return await openEtcatStream(
        connection,
        { kind: "server_port", port },
        Math.min(STREAM_OPEN_ATTEMPT_MS, remaining),
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!message.includes("DeadlineExceeded")) throw error;
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
  }
}

function encodeFileFrameHeader(name: string, size: number, mime: string): Uint8Array {
  const header = new TextEncoder().encode(JSON.stringify({ name, size, mime }));
  const frame = new Uint8Array(FILE_FRAME_MAGIC.byteLength + 4 + header.byteLength);
  frame.set(FILE_FRAME_MAGIC, 0);
  new DataView(frame.buffer).setUint32(FILE_FRAME_MAGIC.byteLength, header.byteLength, true);
  frame.set(header, FILE_FRAME_MAGIC.byteLength + 4);
  return frame;
}

async function runSend(
  transfer: Transfer,
  token: string,
  size: number,
  reader: (offset: number, length: number) => Promise<Uint8Array>,
): Promise<void> {
  const { connected, onEvent } = waitForRelayEvent();
  // Files travel on port 2 with a metadata frame; text stays raw on port 1.
  const isFile = transfer.kind === "file" && transfer.name !== null;
  const port = isFile ? FILE_META_PORT : 1;
  let connection;
  let stream: EasyTierTcpStream | undefined;
  try {
    connection = await connectEtcatBrowser(
      requireWasmModule(),
      token,
      onEvent,
    );
    await withTimeout(
      connected,
      RELAY_CONNECT_TIMEOUT_MS,
      "Timed out connecting to the relay; browsers need a reachable ws:// or wss:// EasyTier relay",
    );
    stream = await openStreamWithRetry(connection, port);
    transfer.status = "transferring";
    transfer.startedAt = Date.now();
    if (isFile) {
      const frameHeader = encodeFileFrameHeader(
        transfer.name!,
        size,
        transfer.mime ?? "application/octet-stream",
      );
      await writeAllStream(stream, frameHeader);
    }
    const sent = await transferPayload(stream, size, reader, (bytes) => {
      transfer.bytes = bytes;
      testState.sentBytes = bytes;
    });
    transfer.status = "confirming";
    testState.sentBytes = sent;
    testState.sentDone = true;
    transfer.status = "done";
  } catch (error) {
    transfer.status = "failed";
    transfer.error = recordError(error);
    throw error;
  } finally {
    await stream?.close().catch(() => undefined);
    await connection?.runtime.stop().catch(() => undefined);
  }
}

async function writeAllStream(
  stream: Pick<EasyTierTcpStream, "write">,
  data: Uint8Array,
): Promise<void> {
  let offset = 0;
  while (offset < data.byteLength) {
    const written = await stream.write(data.subarray(offset));
    if (!Number.isInteger(written) || written <= 0 || written > data.byteLength - offset) {
      throw new Error(`Invalid TCP write length ${written}`);
    }
    offset += written;
  }
}

/** Token for the next send, set by the send panel. */
export const pendingSend = reactive({ token: "" });

// Payloads larger than this stay out of the in-memory buffer; the browser
// receive path is designed for files up to a few hundred MiB.
const MAX_BUFFERED_RECEIVE_BYTES = 512 * 1024 * 1024;
// Only decode payloads up to this size when sniffing for text.
const MAX_TEXT_SNIFF_BYTES = 16 * 1024 * 1024;

interface FileFrameMeta {
  name: string;
  size?: number;
  mime?: string;
}

/**
 * Reads the leading bytes of a stream and, when the file-frame magic is
 * present, parses the metadata header. Returns the metadata plus any payload
 * bytes already read past the header. Raw streams come back with no meta and
 * the peeked bytes as `head`.
 */
async function readFrameHead(
  stream: Pick<EasyTierTcpStream, "read">,
): Promise<{ meta: FileFrameMeta | null; head: Uint8Array[]; headBytes: number }> {
  const MAGIC_LEN = 8;
  const collected: Uint8Array[] = [];
  let collectedBytes = 0;
  let hitEof = false;
  const pull = async (need: number): Promise<void> => {
    while (collectedBytes < need && !hitEof) {
      const result = await stream.read(65536);
      if (result.data.byteLength === 0 && result.eof) {
        hitEof = true;
        break;
      }
      collected.push(result.data);
      collectedBytes += result.data.byteLength;
    }
  };

  await pull(MAGIC_LEN);
  if (collectedBytes < MAGIC_LEN) {
    // Stream too short to carry a frame header: treat as raw payload.
    return { meta: null, head: collected, headBytes: collectedBytes };
  }
  const magic = joinHead(collected, MAGIC_LEN);
  if (!magic.every((byte, index) => byte === FILE_FRAME_MAGIC[index])) {
    // A recognized frame-family prefix with an unknown version is a hard
    // error; anything else is a raw stream.
    const FAMILY = FILE_FRAME_MAGIC.subarray(0, 6);
    if (FAMILY.every((byte, index) => magic[index] === byte)) {
      throw new Error(
        `unsupported file frame version: expected ${new TextDecoder().decode(FILE_FRAME_MAGIC)}, got ${new TextDecoder().decode(magic)}`,
      );
    }
    return { meta: null, head: collected, headBytes: collectedBytes };
  }

  await pull(MAGIC_LEN + 4);
  if (collectedBytes < MAGIC_LEN + 4) {
    throw new Error("stream ended inside the file frame header");
  }
  const headerLen = new DataView(
    joinHead(collected, MAGIC_LEN + 4).buffer,
  ).getUint32(MAGIC_LEN, true);
  if (headerLen > 64 * 1024) {
    throw new Error("file metadata header too large");
  }

  await pull(MAGIC_LEN + 4 + headerLen);
  if (collectedBytes < MAGIC_LEN + 4 + headerLen) {
    throw new Error("stream ended inside the file frame header");
  }
  const headAll = joinHead(collected, collectedBytes);
  const meta = JSON.parse(
    new TextDecoder().decode(headAll.subarray(MAGIC_LEN + 4, MAGIC_LEN + 4 + headerLen)),
  ) as FileFrameMeta;
  if (typeof meta.name !== "string" || meta.name.length === 0) {
    throw new Error("file metadata is missing a name");
  }
  // Sanitize: basename only, strip control characters, bound the length.
  meta.name = meta.name
    .split(/[\\/]/)
    .pop()!
    .replaceAll(/[\x00-\x1f\x7f]/g, "")
    .slice(0, 255);
  if (meta.name.length === 0) {
    throw new Error("file metadata name is empty after sanitization");
  }
  if (meta.mime !== undefined && typeof meta.mime !== "string") {
    meta.mime = undefined;
  }

  const payloadStart = MAGIC_LEN + 4 + headerLen;
  return {
    meta,
    head: [headAll.subarray(payloadStart)],
    headBytes: headAll.byteLength - payloadStart,
  };
}

function joinHead(chunks: Uint8Array[], length: number): Uint8Array {
  const out = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    const slice = chunk.subarray(0, Math.min(chunk.byteLength, length - offset));
    out.set(slice, offset);
    offset += slice.byteLength;
    if (offset >= length) break;
  }
  return out;
}

function handleIncoming(
  connection: EtcatBrowserIncomingConnection,
  sinkHash: boolean,
): Promise<void> {
  const { stream } = connection;
  if (sinkHash) {
    return (async () => {
      try {
        const chunks: Uint8Array[] = [];
        const size = await drainPayload(
          stream,
          (chunk) => {
            chunks.push(Uint8Array.from(chunk));
          },
          (bytes) => {
            testState.recvBytes = bytes;
          },
        );
        const bytes = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) {
          bytes.set(chunk, offset);
          offset += chunk.byteLength;
        }
        testState.recvHash = await sha256Hex(bytes);
        testState.recvDone = true;
      } finally {
        await stream.close().catch(() => undefined);
      }
    })();
  }

  // The server closes the stream as soon as the returned promise settles, so
  // resolve only after the payload is fully buffered and presented.
  return (async () => {
    const transfer = addTransfer({
      direction: "receive",
      kind: "stream",
      name: null,
      size: null,
    });
    transfer.status = "transferring";
    transfer.startedAt = Date.now();

    // Only port 2 carries frames; port 1 stays raw forever.
    const isFramePort =
      connection.destination.kind === "server_port" &&
      connection.destination.port === FILE_META_PORT;

    const chunks: Uint8Array[] = [];
    let overflow = false;
    try {
      let headBytes = 0;
      if (isFramePort) {
        const head = await readFrameHead(stream);
        headBytes = head.headBytes;
        if (head.meta !== null) {
          transfer.kind = "file";
          transfer.name = head.meta.name;
          transfer.mime = head.meta.mime ?? null;
          if (typeof head.meta.size === "number") transfer.size = head.meta.size;
        }
        for (const chunk of head.head) {
          if (chunk.byteLength > 0) chunks.push(Uint8Array.from(chunk));
        }
        transfer.bytes = headBytes;
      }
      const total = await drainPayload(
        stream,
        (chunk) => {
          if (transfer.bytes + chunk.byteLength > MAX_BUFFERED_RECEIVE_BYTES) {
            overflow = true;
            throw new Error("payload exceeds the browser receive limit");
          }
          chunks.push(Uint8Array.from(chunk));
        },
        (bytes) => {
          transfer.bytes = headBytes + bytes;
        },
      );
      transfer.bytes = headBytes + total;
      presentReceivedPayload(transfer, chunks, headBytes + total);
      transfer.status = "done";
    } catch (error) {
      transfer.status = "failed";
      transfer.error = overflow
        ? "i18n:transfer.tooLarge"
        : recordError(error);
    } finally {
      await stream.close().catch(() => undefined);
    }
  })();
}

/** Magic-byte MIME sniffing for payloads that arrive without a header. */
function sniffMime(head: Uint8Array): string | null {
  if (head.byteLength < 4) return null;
  const b = head;
  // Images
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return "image/gif";
  if (b[0] === 0x42 && b[1] === 0x4d) return "image/bmp";
  if (b[0] === 0x00 && b[1] === 0x00 && b[2] === 0x01 && b[3] === 0x00) return "image/x-icon";
  if (
    b.byteLength >= 12 &&
    b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
    b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50
  ) return "image/webp";
  // AVIF: ftyp box with brand avif/avis
  if (
    b.byteLength >= 12 &&
    b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70 &&
    b[8] === 0x61 && b[9] === 0x76 && b[10] === 0x69
  ) return "image/avif";
  // Documents
  if (b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46) return "application/pdf";
  // Video / audio
  if (
    b.byteLength >= 8 &&
    b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70 &&
    !(b[8] === 0x61 && b[9] === 0x76 && b[10] === 0x69)
  ) return "video/mp4";
  if (b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3) return "video/webm";
  if (b[0] === 0x4f && b[1] === 0x67 && b[2] === 0x67 && b[3] === 0x53) return "audio/ogg";
  if (b[0] === 0x66 && b[1] === 0x4c && b[2] === 0x61 && b[3] === 0x43) return "audio/flac";
  if (
    b.byteLength >= 12 &&
    b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
    b[8] === 0x57 && b[9] === 0x41 && b[10] === 0x56 && b[11] === 0x45
  ) return "audio/wav";
  if (
    (b[0] === 0x49 && b[1] === 0x44 && b[2] === 0x33) ||
    (b[0] === 0xff && (b[1] === 0xfb || b[1] === 0xf3 || b[1] === 0xf2))
  ) return "audio/mpeg";
  return null;
}

function presentReceivedPayload(
  transfer: Transfer,
  chunks: Uint8Array[],
  total: number,
): void {
  const head = joinHead(chunks, Math.min(16, chunks.reduce((sum, c) => sum + c.byteLength, 0)));
  const sniffedMime = transfer.mime ?? sniffMime(head);

  const headerIdentifiedFile = transfer.kind === "file" && transfer.name !== null;
  if (!headerIdentifiedFile && sniffedMime === null && total <= MAX_TEXT_SNIFF_BYTES) {
    // Cheap NUL/control-byte sample first, then a strict UTF-8 decode.
    const sample = joinHead(chunks, Math.min(8192, total));
    let looksBinary = false;
    for (const byte of sample) {
      if (byte === 0) {
        looksBinary = true;
        break;
      }
    }
    if (!looksBinary) {
      const bytes = joinHead(chunks, total);
      try {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        transfer.kind = "text";
        transfer.receivedText = text;
        // Upgrade recognizable text formats so the card can render them.
        const trimmed = text.trimStart();
        if (/^<svg[\s>]/i.test(trimmed) || /^<\?xml[\s\S]{0,200}?<svg[\s>]/i.test(trimmed)) {
          transfer.mime = "image/svg+xml";
        } else if (transfer.name?.endsWith(".md") || transfer.name?.endsWith(".markdown")) {
          transfer.mime = "text/markdown";
        } else if (
          (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
          (trimmed.startsWith("[") && trimmed.endsWith("]"))
        ) {
          try {
            JSON.parse(trimmed);
            transfer.mime = "application/json";
          } catch {
            transfer.mime = "text/plain;charset=utf-8";
          }
        } else if (transfer.name?.endsWith(".csv") && trimmed.includes(",")) {
          transfer.mime = "text/csv";
        } else {
          transfer.mime = "text/plain;charset=utf-8";
        }
        return;
      } catch {
        // Not valid UTF-8; fall through to file presentation.
      }
    }
  }
  transfer.kind = "file";
  transfer.mime = sniffedMime ?? transfer.mime;
  transfer.blob = new Blob(chunks as unknown as BlobPart[], {
    type: transfer.mime ?? "application/octet-stream",
  });
  transfer.downloadUrl = URL.createObjectURL(transfer.blob);

  // Text-ish payloads (JSON, CSV, Markdown, SVG, other text/*) get their
  // content decoded for the rich preview even when they arrived as files.
  const mime = transfer.mime ?? "";
  const textish =
    mime === "application/json" ||
    mime === "text/csv" ||
    mime === "text/markdown" ||
    mime === "image/svg+xml" ||
    mime.startsWith("text/");
  if (textish && total <= MAX_TEXT_SNIFF_BYTES) {
    try {
      transfer.receivedText = new TextDecoder("utf-8", { fatal: true }).decode(
        joinHead(chunks, total),
      );
    } catch {
      // Not valid UTF-8; leave the file-only presentation.
    }
  }
}

/**
 * Saves a completed received file. Prefers the File System Access API (the
 * payload was already buffered, so this writes the blob out); falls back to a
 * plain download link click. A cancelled picker is a no-op.
 */
export async function saveReceivedFile(id: number, suggestedName: string): Promise<void> {
  const transfer = store.transfers.find((entry) => entry.id === id);
  if (transfer === undefined || transfer.blob === null) return;
  const picker = (
    window as unknown as {
      showSaveFilePicker?: (options: {
        suggestedName: string;
      }) => Promise<{
        createWritable(): Promise<{
          write(data: Blob): Promise<void>;
          close(): Promise<void>;
          abort?(): Promise<void>;
        }>;
      }>;
    }
  ).showSaveFilePicker;

  if (picker !== undefined) {
    let handle;
    try {
      handle = await picker({ suggestedName });
    } catch (error) {
      // Cancelled picker: the buffered payload stays put; nothing to do.
      if (error instanceof Error && error.name === "AbortError") return;
      throw error;
    }
    const writable = await handle.createWritable();
    try {
      await writable.write(transfer.blob);
      await writable.close();
    } catch (error) {
      await writable.abort?.().catch(() => undefined);
      throw error;
    }
    return;
  }

  if (transfer.downloadUrl !== null) {
    const anchor = document.createElement("a");
    anchor.href = transfer.downloadUrl;
    anchor.download = suggestedName;
    anchor.click();
  }
}

export function removeTransfer(id: number): void {
  const index = store.transfers.findIndex((entry) => entry.id === id);
  if (index === -1) return;
  const [transfer] = store.transfers.splice(index, 1);
  if (transfer !== undefined && transfer.downloadUrl !== null) {
    URL.revokeObjectURL(transfer.downloadUrl);
  }
}

export function clearFinishedTransfers(): void {
  for (const transfer of [...store.transfers]) {
    if (transfer.status === "done" || transfer.status === "failed") {
      removeTransfer(transfer.id);
    }
  }
}

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
        destination.kind === "server_port" && destination.port === 1
          ? true
          : "the browser transfer listener only accepts server port 1",
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
  reader: (offset: number, length: number) => Promise<Uint8Array>,
): Promise<void> {
  // Capture the token now: the queued payload must go to the receiver chosen
  // at submit time, not to whatever the input holds when the queue drains.
  const token = normalizeToken(pendingSend.token);
  // Serialize sends: one connection at a time keeps status readable and
  // avoids competing relay sessions.
  const run = sendQueue.then(() => sendPayload(token, name, kind, size, reader));
  sendQueue = run.catch(() => undefined);
  return run;
}

async function sendPayload(
  token: string,
  name: string | null,
  kind: "file" | "text",
  size: number,
  reader: (offset: number, length: number) => Promise<Uint8Array>,
): Promise<void> {
  const transfer = addTransfer({ direction: "send", kind, name, size });
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
        { kind: "server_port", port: 1 },
        Math.min(STREAM_OPEN_ATTEMPT_MS, remaining),
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!message.includes("DeadlineExceeded")) throw error;
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
  }
}

async function runSend(
  transfer: Transfer,
  token: string,
  size: number,
  reader: (offset: number, length: number) => Promise<Uint8Array>,
): Promise<void> {
  const { connected, onEvent } = waitForRelayEvent();
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
    stream = await openStreamWithRetry(connection);
    transfer.status = "transferring";
    transfer.startedAt = Date.now();
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

/** Token for the next send, set by the send panel. */
export const pendingSend = reactive({ token: "" });

// Payloads larger than this stay out of the in-memory buffer; the browser
// receive path is designed for files up to a few hundred MiB.
const MAX_BUFFERED_RECEIVE_BYTES = 512 * 1024 * 1024;
// Only decode payloads up to this size when sniffing for text.
const MAX_TEXT_SNIFF_BYTES = 16 * 1024 * 1024;

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

  const transfer = addTransfer({
    direction: "receive",
    kind: "stream",
    name: null,
    size: null,
  });
  transfer.status = "transferring";
  transfer.startedAt = Date.now();

  // The server closes the stream as soon as the returned promise settles, so
  // resolve only after the payload is fully buffered and presented.
  return (async () => {
    const chunks: Uint8Array[] = [];
    let overflow = false;
    try {
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
          transfer.bytes = bytes;
        },
      );
      transfer.bytes = total;
      presentReceivedPayload(transfer, chunks, total);
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

function presentReceivedPayload(
  transfer: Transfer,
  chunks: Uint8Array[],
  total: number,
): void {
  // Text sniffing: cheap NUL/control-byte sample first, then a strict UTF-8
  // decode. Binary payloads become a downloadable blob instead.
  if (total <= MAX_TEXT_SNIFF_BYTES) {
    const sample = chunks[0]?.subarray(0, 8192) ?? new Uint8Array();
    let looksBinary = false;
    for (const byte of sample) {
      if (byte === 0) {
        looksBinary = true;
        break;
      }
    }
    if (!looksBinary) {
      const bytes = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
      try {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        transfer.kind = "text";
        transfer.receivedText = text;
        return;
      } catch {
        // Not valid UTF-8; fall through to file presentation.
      }
    }
  }
  transfer.kind = "file";
  transfer.blob = new Blob(chunks as unknown as BlobPart[]);
  transfer.downloadUrl = URL.createObjectURL(transfer.blob);
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

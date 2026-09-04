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
const STREAM_OPEN_TIMEOUT_MS = 5_000;

export type TransferStatus =
  | "connecting"
  | "transferring"
  | "confirming"
  | "awaiting-choice"
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
  /** Completed received payload, when the user chose to view it. */
  receivedText: string | null;
  /** Blob URL for a completed received file buffered in memory. */
  downloadUrl: string | null;
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
        } else if (event.kind === "connect_error") {
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
  await current?.close().catch(() => undefined);
}

export function closeListenerOnPageHide(): void {
  window.addEventListener("pagehide", () => {
    void server?.close();
  });
}

export function enqueueSend(
  name: string | null,
  kind: "file" | "text",
  size: number,
  reader: (offset: number, length: number) => Promise<Uint8Array>,
): Promise<void> {
  // Serialize sends: one connection at a time keeps status readable and
  // avoids competing relay sessions.
  const run = sendQueue.then(() => sendPayload(name, kind, size, reader));
  sendQueue = run.catch(() => undefined);
  return run;
}

async function sendPayload(
  name: string | null,
  kind: "file" | "text",
  size: number,
  reader: (offset: number, length: number) => Promise<Uint8Array>,
): Promise<void> {
  const transfer = addTransfer({ direction: "send", kind, name, size });
  const token = pendingSend.token.trim();
  if (token.length === 0) {
    transfer.status = "failed";
    transfer.error = recordError(new Error("Enter an etc2 receiver token first"));
    throw new Error(transfer.error);
  }
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
    stream = await openEtcatStream(
      connection,
      { kind: "server_port", port: 1 },
      STREAM_OPEN_TIMEOUT_MS,
    );
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
  transfer.status = "awaiting-choice";
  // The server closes the stream as soon as the returned promise settles, so
  // stay pending until the user-chosen receive path finishes.
  return new Promise<void>((resolve) => {
    pendingIncoming.set(transfer.id, { stream, transfer, resolve });
  });
}

interface PendingIncoming {
  stream: EasyTierTcpStream;
  transfer: Transfer;
  resolve: () => void;
}

const pendingIncoming = new Map<number, PendingIncoming>();

export async function receiveAsText(id: number): Promise<void> {
  const pending = pendingIncoming.get(id);
  if (pending === undefined) return;
  pendingIncoming.delete(id);
  const { stream, transfer, resolve } = pending;
  transfer.status = "transferring";
  transfer.startedAt = Date.now();
  try {
    const decoder = new TextDecoder();
    let text = "";
    const total = await drainPayload(
      stream,
      (chunk) => {
        text += decoder.decode(chunk, { stream: true });
      },
      (bytes) => {
        transfer.bytes = bytes;
      },
    );
    text += decoder.decode();
    transfer.receivedText = text;
    transfer.kind = "text";
    transfer.bytes = total;
    transfer.status = "done";
  } catch (error) {
    transfer.status = "failed";
    transfer.error = recordError(error);
  } finally {
    await stream.close().catch(() => undefined);
    resolve();
  }
}

export async function receiveAsFile(id: number, suggestedName: string): Promise<void> {
  const pending = pendingIncoming.get(id);
  if (pending === undefined) return;
  pendingIncoming.delete(id);
  const { stream, transfer, resolve } = pending;
  transfer.status = "transferring";
  transfer.kind = "file";
  transfer.name = suggestedName;
  transfer.startedAt = Date.now();

  try {
    const picker = (
      window as unknown as {
        showSaveFilePicker?: (options: {
          suggestedName: string;
        }) => Promise<{
          createWritable(): Promise<{
            write(data: Uint8Array): Promise<void>;
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
        // A cancelled picker must not drop the payload: the stream is still
        // open and unconsumed, so hand the choice back to the user.
        if (error instanceof Error && error.name === "AbortError") {
          transfer.status = "awaiting-choice";
          pendingIncoming.set(id, { stream, transfer, resolve });
          return;
        }
        throw error;
      }
      const writable = await handle.createWritable();
      try {
        const total = await drainPayload(
          stream,
          (chunk) => writable.write(chunk),
          (bytes) => {
            transfer.bytes = bytes;
          },
        );
        await writable.close();
        transfer.bytes = total;
      } catch (error) {
        await writable.abort?.().catch(() => undefined);
        throw error;
      }
    } else {
      const chunks: Uint8Array[] = [];
      const total = await drainPayload(
        stream,
        (chunk) => {
          chunks.push(Uint8Array.from(chunk));
        },
        (bytes) => {
          transfer.bytes = bytes;
        },
      );
      const blob = new Blob(chunks as unknown as BlobPart[]);
      transfer.downloadUrl = URL.createObjectURL(blob);
      transfer.bytes = total;
    }
    transfer.status = "done";
  } catch (error) {
    transfer.status = "failed";
    transfer.error = recordError(error);
  } finally {
    await stream.close().catch(() => undefined);
    resolve();
  }
}

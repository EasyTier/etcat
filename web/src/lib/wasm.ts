import { reactive, readonly } from "vue";

export type WasmStatus =
  | { kind: "loading"; progress: number }
  | { kind: "ready"; module: WebAssembly.Module }
  | { kind: "failed"; message: string };

interface WasmState {
  status: WasmStatus;
}

const state = reactive<WasmState>({
  status: { kind: "loading", progress: 0 },
});

let started = false;

async function load(): Promise<void> {
  const response = await fetch("./easytier_core.wasm");
  if (!response.ok) {
    throw new Error(`Failed to load EasyTier WebAssembly: HTTP ${response.status}`);
  }
  const total = Number(response.headers.get("Content-Length")) || 0;
  const chunks: Uint8Array[] = [];
  let loaded = 0;
  if (response.body === null) {
    chunks.push(new Uint8Array(await response.arrayBuffer()));
    loaded = chunks[0]!.byteLength;
  } else {
    const reader = response.body.getReader();
    for (;;) {
      const result = await reader.read();
      if (result.done) break;
      chunks.push(result.value);
      loaded += result.value.byteLength;
      if (total > 0) {
        state.status = { kind: "loading", progress: loaded / total };
      }
    }
  }
  const bytes = new Uint8Array(loaded);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  // JSPI modules must be compiled, not streamed, so construct explicitly.
  const WasmModule = WebAssembly.Module as unknown as new (
    contents: BufferSource,
  ) => WebAssembly.Module;
  state.status = { kind: "ready", module: new WasmModule(bytes) };
}

export function startWasmLoad(): void {
  if (started) return;
  started = true;
  load().catch((error: unknown) => {
    state.status = {
      kind: "failed",
      message: error instanceof Error ? error.message : String(error),
    };
  });
}

export function useWasm(): Readonly<WasmState> {
  return readonly(state);
}

export function requireWasmModule(): WebAssembly.Module {
  if (state.status.kind !== "ready") {
    throw new Error("WebAssembly module is not ready");
  }
  return state.status.module;
}

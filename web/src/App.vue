<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { Download, ShieldCheck, Upload } from "lucide-vue-next";
import {
  TabsContent,
  TabsList,
  TabsRoot,
  TabsTrigger,
} from "reka-ui";
import ReceivePanel from "./components/ReceivePanel.vue";
import SendPanel from "./components/SendPanel.vue";
import { startListener, closeListenerOnPageHide, enqueueSend, pendingSend } from "@/lib/transfers";
import { installTestHooks, queryAutomation, recordError, testState } from "@/lib/testhooks";
import { sha256Hex } from "@/lib/runtime";
import { startWasmLoad, useWasm } from "@/lib/wasm";

// Must run before any transfer state changes so the smoke harness always
// observes the reactive state object.
installTestHooks();

const wasm = useWasm();
const mode = ref<"receive" | "send">("receive");
const startupError = ref<string | null>(null);

const wasmReady = computed(() => wasm.status.kind === "ready");

const loadPercent = computed(() =>
  wasm.status.kind === "loading"
    ? Math.floor(wasm.status.progress * 100)
    : wasm.status.kind === "ready"
      ? 100
      : 0,
);

function randomPayload(size: number): Uint8Array {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new Error("The bytes query parameter must be a non-negative safe integer");
  }
  const data = new Uint8Array(size);
  for (let offset = 0; offset < size; offset += 64 * 1024) {
    crypto.getRandomValues(
      data.subarray(offset, Math.min(offset + 64 * 1024, size)),
    );
  }
  return data;
}

onMounted(async () => {
  startWasmLoad();
  closeListenerOnPageHide();
  const automation = queryAutomation();

  // Share links prefill the token and jump straight to the send panel.
  if (automation.token !== null && automation.mode === null) {
    pendingSend.token = automation.token;
    mode.value = "send";
  }

  // Smoke-harness automations (kept compatible with the legacy page).
  try {
    if (automation.mode === "listen") {
      await waitForWasm();
      await startListener(automation.sinkHash);
    } else if (automation.mode === "send") {
      if (automation.token === null) {
        throw new Error("The token query parameter is required in send mode");
      }
      if (automation.bytes === null) {
        throw new Error("The bytes query parameter is required in send mode");
      }
      pendingSend.token = automation.token;
      mode.value = "send";
      await waitForWasm();
      const data = randomPayload(automation.bytes);
      testState.sentHash = await sha256Hex(data);
      await enqueueSend(null, "file", data.byteLength, async (offset, length) => {
        return data.subarray(offset, offset + length);
      }).catch((error: unknown) => {
        startupError.value =
          error instanceof Error ? error.message : String(error);
      });
    }
  } catch (error) {
    startupError.value = recordError(error);
  }
});

async function waitForWasm(): Promise<void> {
  for (;;) {
    if (wasm.status.kind === "ready") return;
    if (wasm.status.kind === "failed") {
      throw new Error(wasm.status.message);
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

// Flip the test-ready flag only once the module is actually usable.
watch(wasmReady, (ready) => {
  if (ready) testState.ready = true;
});
</script>

<template>
  <main class="mx-auto min-h-screen w-full max-w-xl px-4 py-10 sm:py-16">
    <header class="mb-8 text-center">
      <div class="mb-2 inline-flex items-center gap-2">
        <span
          class="bg-gradient-to-r from-accent to-glow bg-clip-text font-mono text-3xl font-bold tracking-tight text-transparent"
        >
          etcat
        </span>
      </div>
      <p class="text-sm text-slate-500">
        Peer-to-peer file &amp; text transfer, right in your browser
      </p>
      <p class="mt-2 inline-flex items-center gap-1.5 text-xs text-slate-600">
        <ShieldCheck class="size-3.5 text-accent/70" />
        End-to-end encrypted via EasyTier — relays never see your data
      </p>
    </header>

    <div
      v-if="wasm.status.kind === 'loading'"
      class="rounded-xl border border-edge bg-panel/80 p-4"
    >
      <div class="mb-2 flex items-center justify-between text-xs text-slate-400">
        <span>Loading WebAssembly runtime…</span>
        <span class="tabular-nums">{{ loadPercent }}%</span>
      </div>
      <div class="h-1.5 overflow-hidden rounded-full bg-edge">
        <div
          class="h-full rounded-full bg-gradient-to-r from-accent to-glow transition-[width] duration-200"
          :style="{ width: `${loadPercent}%` }"
        />
      </div>
    </div>

    <div
      v-else-if="wasm.status.kind === 'failed'"
      class="rounded-xl border border-rose-400/30 bg-rose-500/10 p-4 text-sm text-rose-300"
    >
      Failed to load the WebAssembly runtime: {{ wasm.status.message }}
    </div>

    <template v-else>
      <div
        v-if="startupError !== null"
        class="mb-4 rounded-lg border border-rose-400/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300"
      >
        {{ startupError }}
      </div>

      <TabsRoot v-model="mode">
        <TabsList
          class="mb-5 grid grid-cols-2 gap-1 rounded-xl border border-edge bg-panel/60 p-1"
        >
          <TabsTrigger
            value="receive"
            class="inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium text-slate-400 transition data-[state=active]:bg-accent/15 data-[state=active]:text-accent"
          >
            <Download class="size-4" />
            Receive
          </TabsTrigger>
          <TabsTrigger
            value="send"
            class="inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium text-slate-400 transition data-[state=active]:bg-accent/15 data-[state=active]:text-accent"
          >
            <Upload class="size-4" />
            Send
          </TabsTrigger>
        </TabsList>
        <TabsContent value="receive">
          <ReceivePanel />
        </TabsContent>
        <TabsContent value="send">
          <SendPanel />
        </TabsContent>
      </TabsRoot>
    </template>

    <footer class="mt-10 text-center text-xs text-slate-600">
      <a
        href="https://github.com/EasyTier/etcat"
        class="transition hover:text-slate-400"
        target="_blank"
        rel="noopener"
      >
        github.com/EasyTier/etcat
      </a>
    </footer>
  </main>
</template>

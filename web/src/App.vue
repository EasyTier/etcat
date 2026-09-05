<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { ShieldCheck } from "lucide-vue-next";
import TopBar from "./components/TopBar.vue";
import SideNav from "./components/SideNav.vue";
import ModeCards from "./components/ModeCards.vue";
import ReceivePanel from "./components/ReceivePanel.vue";
import SendPanel from "./components/SendPanel.vue";
import AdvancedSettings from "./components/AdvancedSettings.vue";
import { useI18n } from "@/lib/i18n";
import { startListener, closeListenerOnPageHide, enqueueSend, pendingSend, store } from "@/lib/transfers";
import { installTestHooks, queryAutomation, recordError, testState } from "@/lib/testhooks";
import { sha256Hex } from "@/lib/runtime";
import { startWasmLoad, useWasm } from "@/lib/wasm";

// Must run before any transfer state changes so the smoke harness always
// observes the reactive state object.
installTestHooks();

const wasm = useWasm();
const { t } = useI18n();
const mode = ref<"receive" | "send">("receive");
const startupError = ref<string | null>(null);
const settingsOpen = ref(false);

const wasmReady = computed(() => wasm.status.kind === "ready");

watch(
  () => store.listener.kind,
  (kind) => {
    document.title = kind === "listening" ? "● etcat" : "etcat";
  },
);

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
  <div class="flex h-screen flex-col">
    <TopBar />
    <div class="flex min-h-0 flex-1">
      <SideNav @open-settings="settingsOpen = true" />

      <main class="nice-scroll min-w-0 flex-1 overflow-y-auto">
        <div class="mx-auto max-w-3xl px-6 py-10">
          <div
            v-if="wasm.status.kind === 'loading'"
            class="card-glow animate-rise rounded-2xl p-6"
          >
            <div class="mb-3 flex items-center justify-between text-sm text-slate-400">
              <span>{{ t("app.loading") }}</span>
              <span class="tabular-nums">{{ loadPercent }}%</span>
            </div>
            <div class="h-2 overflow-hidden rounded-full bg-edge">
              <div
                class="h-full rounded-full bg-gradient-to-r from-accent to-glow transition-[width] duration-200"
                :style="{ width: `${loadPercent}%` }"
              />
            </div>
          </div>

          <div
            v-else-if="wasm.status.kind === 'failed'"
            class="rounded-2xl border border-rose-400/30 bg-rose-500/10 p-5 text-sm text-rose-300"
          >
            {{ t("app.loadFailed") }}: {{ wasm.status.message }}
          </div>

          <template v-else>
            <div
              v-if="startupError !== null"
              class="mb-4 rounded-xl border border-rose-400/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-300"
            >
              {{ startupError }}
            </div>

            <ModeCards v-model="mode" />

            <div class="mt-6">
              <ReceivePanel v-show="mode === 'receive'" />
              <SendPanel v-show="mode === 'send'" />
            </div>
          </template>

          <footer class="mt-14 flex items-center justify-center gap-2 text-xs text-slate-600">
            <ShieldCheck class="size-3.5 text-accent/60" />
            {{ t("app.encrypted") }}
            <span aria-hidden="true">·</span>
            <a
              href="https://github.com/EasyTier/etcat"
              class="transition hover:text-slate-400"
              target="_blank"
              rel="noopener"
            >
              github.com/EasyTier/etcat
            </a>
          </footer>
        </div>
      </main>
    </div>

    <!-- Settings drawer -->
    <Teleport to="body">
      <div
        v-if="settingsOpen"
        class="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm"
        @click="settingsOpen = false"
      />
      <div
        class="fixed inset-y-0 right-0 z-50 w-80 transform border-l border-edge bg-panel shadow-2xl transition-transform duration-300"
        :class="settingsOpen ? 'translate-x-0' : 'translate-x-full'"
        :inert="!settingsOpen"
      >
        <div class="flex items-center justify-between border-b border-edge px-5 py-4">
          <span class="text-sm font-semibold text-slate-200">{{ t("advanced.title") }}</span>
          <button
            type="button"
            class="rounded-lg p-1.5 text-slate-500 transition hover:bg-white/5 hover:text-slate-200"
            @click="settingsOpen = false"
          >
            ✕
          </button>
        </div>
        <div class="p-5">
          <AdvancedSettings bare />
        </div>
      </div>
    </Teleport>
  </div>
</template>

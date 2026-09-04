<script setup lang="ts">
import { computed } from "vue";
import { Radio, Square } from "lucide-vue-next";
import AdvancedSettings from "./AdvancedSettings.vue";
import TokenCard from "./TokenCard.vue";
import TransferCard from "./TransferCard.vue";
import { startListener, stopListener, store } from "@/lib/transfers";
import { useWasm } from "@/lib/wasm";

const wasm = useWasm();

const incoming = computed(() =>
  store.transfers.filter((transfer) => transfer.direction === "receive"),
);

const listening = computed(() => store.listener.kind === "listening");
const starting = computed(() => store.listener.kind === "starting");

async function toggle(): Promise<void> {
  if (listening.value) {
    await stopListener();
  } else {
    await startListener(new URLSearchParams(window.location.search).get("sink") === "hash");
  }
}
</script>

<template>
  <div class="space-y-4">
    <p class="text-sm text-slate-400">
      Create a listener and share its token. The sender can use this page or the
      CLI: <code class="rounded bg-black/40 px-1.5 py-0.5 font-mono text-xs text-slate-300">etcat &lt;token&gt; &lt; file</code>
    </p>

    <button
      type="button"
      :disabled="wasm.status.kind !== 'ready' || starting"
      class="inline-flex w-full items-center justify-center gap-2 rounded-xl px-4 py-3 text-sm font-semibold transition"
      :class="
        listening
          ? 'border border-rose-400/40 bg-rose-500/10 text-rose-300 hover:bg-rose-500/20'
          : 'bg-accent text-void hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40'
      "
      @click="toggle"
    >
      <Square v-if="listening" class="size-4" />
      <Radio v-else class="size-4" />
      {{ listening ? "Stop listening" : starting ? "Starting listener…" : "Start receiving" }}
    </button>

    <div
      v-if="store.listener.kind === 'failed'"
      class="rounded-lg border border-rose-400/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300"
    >
      {{ store.listener.message }}
    </div>

    <TokenCard />

    <div
      v-if="listening && store.listener.kind === 'listening' && !store.listener.relayReady"
      class="flex items-center gap-2 text-xs text-amber-300"
    >
      <span class="pulse-dot inline-block size-2 rounded-full bg-amber-300" />
      Connecting to the relay…
    </div>
    <div
      v-else-if="listening"
      class="flex items-center gap-2 text-xs text-emerald-300"
    >
      <span class="pulse-dot inline-block size-2 rounded-full bg-emerald-300" />
      Listening — waiting for a sender
    </div>

    <div v-if="incoming.length > 0" class="space-y-3">
      <TransferCard
        v-for="transfer in incoming"
        :key="transfer.id"
        :transfer="transfer"
      />
    </div>

    <AdvancedSettings />
  </div>
</template>

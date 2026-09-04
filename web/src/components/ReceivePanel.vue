<script setup lang="ts">
import { computed } from "vue";
import { Radio, Trash2 } from "lucide-vue-next";
import AdvancedSettings from "./AdvancedSettings.vue";
import TokenCard from "./TokenCard.vue";
import TransferCard from "./TransferCard.vue";
import { useI18n } from "@/lib/i18n";
import {
  clearFinishedTransfers,
  startListener,
  stopListener,
  store,
} from "@/lib/transfers";
import { useWasm } from "@/lib/wasm";

const wasm = useWasm();
const { t } = useI18n();

const incoming = computed(() =>
  store.transfers.filter((transfer) => transfer.direction === "receive"),
);

const finishedCount = computed(
  () =>
    store.transfers.filter(
      (transfer) =>
        transfer.status === "done" || transfer.status === "failed",
    ).length,
);

const listening = computed(() => store.listener.kind === "listening");
const starting = computed(() => store.listener.kind === "starting");

async function start(): Promise<void> {
  if (listening.value || starting.value) return;
  await startListener(
    new URLSearchParams(window.location.search).get("sink") === "hash",
  );
}
</script>

<template>
  <div class="space-y-4">
    <ol class="grid grid-cols-3 gap-2 text-center text-xs text-slate-500">
      <li class="rounded-lg border border-edge bg-panel/40 px-2 py-2">
        <span class="mb-0.5 block font-semibold text-accent">1</span>
        {{ t("receive.step1") }}
      </li>
      <li class="rounded-lg border border-edge bg-panel/40 px-2 py-2">
        <span class="mb-0.5 block font-semibold text-accent">2</span>
        {{ t("receive.step2") }}
      </li>
      <li class="rounded-lg border border-edge bg-panel/40 px-2 py-2">
        <span class="mb-0.5 block font-semibold text-accent">3</span>
        {{ t("receive.step3") }}
      </li>
    </ol>

    <div v-if="!listening" class="space-y-2">
      <button
        type="button"
        :disabled="wasm.status.kind !== 'ready' || starting"
        class="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-4 py-3 text-sm font-semibold text-void transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40"
        @click="start"
      >
        <Radio class="size-4" />
        {{ starting ? t("receive.starting") : t("receive.start") }}
      </button>
      <div
        v-if="store.listener.kind === 'failed'"
        class="rounded-lg border border-rose-400/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300"
      >
        {{ t("receive.failed") }}: {{ store.listener.message }}
      </div>
    </div>

    <template v-else>
      <TokenCard />
      <div class="flex items-center justify-between gap-3">
        <div
          v-if="store.listener.kind === 'listening' && !store.listener.relayReady"
          class="flex items-center gap-2 text-xs text-amber-300"
        >
          <span class="pulse-dot inline-block size-2 rounded-full bg-amber-300" />
          {{ t("receive.connecting") }}
        </div>
        <div v-else class="flex items-center gap-2 text-xs text-emerald-300">
          <span class="pulse-dot inline-block size-2 rounded-full bg-emerald-300" />
          {{ t("receive.listening") }}
        </div>
        <button
          type="button"
          class="text-xs text-slate-500 underline-offset-2 transition hover:text-rose-300 hover:underline"
          @click="stopListener"
        >
          {{ t("receive.stop") }}
        </button>
      </div>
    </template>

    <div v-if="incoming.length > 0" class="space-y-3">
      <div v-if="finishedCount > 1" class="flex justify-end">
        <button
          type="button"
          class="inline-flex items-center gap-1 text-xs text-slate-500 transition hover:text-slate-300"
          @click="clearFinishedTransfers"
        >
          <Trash2 class="size-3" />
          {{ t("transfer.clearDone") }}
        </button>
      </div>
      <TransferCard
        v-for="transfer in incoming"
        :key="transfer.id"
        :transfer="transfer"
      />
    </div>

    <AdvancedSettings />
  </div>
</template>

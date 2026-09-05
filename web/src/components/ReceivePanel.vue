<script setup lang="ts">
import { computed } from "vue";
import { Radio, Trash2 } from "lucide-vue-next";
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
      (transfer) => transfer.status === "done" || transfer.status === "failed",
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
  <div class="space-y-6">
    <div v-if="!listening" class="animate-rise">
      <button
        type="button"
        :disabled="wasm.status.kind !== 'ready' || starting"
        class="btn-primary w-full"
        @click="start"
      >
        <Radio class="size-5" />
        {{ starting ? t("receive.starting") : t("receive.start") }}
      </button>
      <div
        v-if="store.listener.kind === 'failed'"
        class="mt-3 rounded-xl border border-rose-400/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-300"
      >
        {{ t("receive.failed") }}: {{ store.listener.message }}
      </div>
      <p class="mt-3 text-center text-sm text-slate-500">
        {{ t("receive.step1") }} · {{ t("receive.step2") }} · {{ t("receive.step3") }}
      </p>
    </div>

    <template v-else>
      <TokenCard />
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-2 text-sm text-emerald-300">
          <span class="pulse-dot inline-block size-2 rounded-full bg-emerald-400" />
          {{ t("receive.listening") }}
        </div>
        <button
          type="button"
          class="text-sm text-slate-500 underline-offset-2 transition hover:text-rose-300 hover:underline"
          @click="stopListener"
        >
          {{ t("receive.stop") }}
        </button>
      </div>
    </template>

    <div v-if="incoming.length > 0" class="space-y-4">
      <div v-if="finishedCount > 1" class="flex justify-end">
        <button
          type="button"
          class="inline-flex items-center gap-1.5 text-sm text-slate-500 transition hover:text-slate-300"
          @click="clearFinishedTransfers"
        >
          <Trash2 class="size-3.5" />
          {{ t("transfer.clearDone") }}
        </button>
      </div>
      <TransferCard
        v-for="transfer in incoming"
        :key="transfer.id"
        :transfer="transfer"
      />
    </div>
  </div>
</template>

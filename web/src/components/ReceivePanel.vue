<script setup lang="ts">
import { computed } from "vue";
import { Inbox, Radio } from "lucide-vue-next";
import TokenCard from "./TokenCard.vue";
import TransferCard from "./TransferCard.vue";
import TransferRow from "./TransferRow.vue";
import { useI18n } from "@/lib/i18n";
import { startListener, stopListener, store } from "@/lib/transfers";
import { useWasm } from "@/lib/wasm";

const wasm = useWasm();
const { t } = useI18n();

const incoming = computed(() =>
  store.transfers.filter((transfer) => transfer.direction === "receive"),
);
const spotlight = computed(() =>
  incoming.value.find(
    (transfer) =>
      transfer.status === "connecting" ||
      transfer.status === "transferring" ||
      transfer.status === "confirming",
  ),
);
const latest = computed(() =>
  incoming.value.find(
    (transfer) => transfer.status === "done" || transfer.status === "failed",
  ),
);
const history = computed(() =>
  incoming.value.filter(
    (transfer) =>
      transfer !== spotlight.value && transfer !== latest.value,
  ),
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
        <div
          v-if="store.listener.kind === 'listening' && !store.listener.relayReady"
          class="flex items-center gap-2 text-sm text-amber-300"
        >
          <span class="pulse-dot inline-block size-2 rounded-full bg-amber-300" />
          {{ t("receive.connecting") }}
        </div>
        <div v-else class="flex items-center gap-2 text-sm text-emerald-300">
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

    <!-- Spotlight: the transfer that matters right now -->
    <TransferCard v-if="spotlight" :transfer="spotlight" />
    <TransferCard v-else-if="latest" :transfer="latest" />

    <div
      v-else-if="listening"
      class="flex flex-col items-center gap-3 rounded-2xl border border-dashed border-edge py-14 text-slate-600"
    >
      <Inbox class="size-8" />
      <span class="text-sm">{{ t("timeline.empty") }}</span>
    </div>

    <div v-if="history.length > 0" class="space-y-0.5">
      <div class="px-3 pb-1 text-xs font-medium tracking-widest text-slate-600 uppercase">
        {{ t("timeline.earlier") }}
      </div>
      <TransferRow
        v-for="transfer in history"
        :key="transfer.id"
        :transfer="transfer"
      />
    </div>
  </div>
</template>

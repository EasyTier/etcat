<script setup lang="ts">
import { computed } from "vue";
import { ArrowLeftRight, Radio } from "lucide-vue-next";
import { useI18n } from "@/lib/i18n";
import { store } from "@/lib/transfers";
import { formatBytes } from "@/lib/format";

const { t } = useI18n();

const emit = defineEmits<{ (e: "open-settings"): void }>();

const listening = computed(() => store.listener.kind === "listening");
const incomingCount = computed(
  () => store.transfers.filter((tr) => tr.direction === "receive").length,
);
const outgoingCount = computed(
  () => store.transfers.filter((tr) => tr.direction === "send").length,
);
const activeCount = computed(
  () =>
    store.transfers.filter(
      (tr) =>
        tr.status === "connecting" ||
        tr.status === "transferring" ||
        tr.status === "confirming",
    ).length,
);
const bufferedBytes = computed(() =>
  store.transfers.reduce((sum, tr) => sum + tr.bytes, 0),
);
</script>

<template>
  <aside
    class="hidden w-60 shrink-0 flex-col border-r border-edge bg-panel/50 backdrop-blur-xl md:flex"
  >
    <nav class="flex-1 space-y-1 overflow-y-auto p-3">
      <div class="px-3 pb-2 text-xs font-semibold tracking-widest text-slate-600 uppercase">
        {{ t("nav.transfer") }}
      </div>
      <button
        type="button"
        class="flex w-full items-center gap-3 rounded-xl bg-accent/10 px-3 py-3 text-left"
      >
        <span
          class="flex size-9 items-center justify-center rounded-lg bg-gradient-to-br from-accent/25 to-glow/25 text-accent"
        >
          <ArrowLeftRight class="size-4.5" />
        </span>
        <span class="min-w-0">
          <span class="block text-sm font-medium text-slate-100">{{ t("nav.transfer") }}</span>
          <span class="block truncate text-xs text-slate-500">{{ t("nav.transferHint") }}</span>
        </span>
      </button>

      <template v-if="listening || incomingCount + outgoingCount > 0">
        <div class="px-3 pt-5 pb-2 text-xs font-semibold tracking-widest text-slate-600 uppercase">
          {{ t("nav.connections") }}
        </div>
        <div
          v-if="listening"
          class="flex items-center gap-3 rounded-xl px-3 py-2.5"
        >
          <span class="pulse-dot inline-block size-2 rounded-full bg-emerald-400" />
          <span class="min-w-0 flex-1">
            <span class="block truncate text-sm text-slate-300">{{ t("conn.myListener") }}</span>
          </span>
          <Radio class="size-3.5 shrink-0 text-emerald-400" />
        </div>
        <div
          v-if="incomingCount + outgoingCount > 0"
          class="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-slate-400"
        >
          <span class="flex-1 truncate">
            {{ incomingCount }} {{ t("conn.incoming") }} · {{ outgoingCount }} {{ t("conn.outgoing") }}
          </span>
          <span class="shrink-0 tabular-nums text-xs text-slate-600">
            {{ formatBytes(bufferedBytes) }}
          </span>
        </div>
      </template>
    </nav>

    <div class="border-t border-edge p-3">
      <button
        type="button"
        class="flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-sm text-slate-400 transition hover:bg-white/5 hover:text-slate-200"
        @click="emit('open-settings')"
      >
        {{ t("advanced.title") }}
        <span v-if="activeCount > 0" class="text-xs text-accent tabular-nums">{{ activeCount }} ⇄</span>
      </button>
    </div>
  </aside>
</template>

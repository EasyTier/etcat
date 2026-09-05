<script setup lang="ts">
import { computed } from "vue";
import { ArrowDownToLine, ArrowUpFromLine, FileText } from "lucide-vue-next";
import { formatBytes } from "@/lib/format";
import { useI18n } from "@/lib/i18n";
import { removeTransfer, type Transfer } from "@/lib/transfers";

const props = defineProps<{ transfer: Transfer }>();
const { t } = useI18n();

const icon = computed(() =>
  props.transfer.direction === "receive" ? ArrowDownToLine : ArrowUpFromLine,
);

const title = computed(() => {
  if (props.transfer.direction === "send") {
    return props.transfer.kind === "text"
      ? t("transfer.sendTextTitle")
      : props.transfer.name ?? t("transfer.sendTitle");
  }
  return props.transfer.kind === "text"
    ? t("transfer.recvTextTitle")
    : t("transfer.recvFileTitle");
});

const ago = computed(() => {
  const seconds = Math.floor((Date.now() - props.transfer.startedAt) / 1000);
  if (seconds < 60) return t("timeline.justNow");
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}${t("timeline.minutesAgo")}`;
  return `${Math.floor(minutes / 60)}${t("timeline.hoursAgo")}`;
});

const failed = computed(() => props.transfer.status === "failed");
</script>

<template>
  <div
    class="group flex items-center gap-3 rounded-xl px-3 py-2 transition hover:bg-white/5"
  >
    <span
      class="flex size-8 shrink-0 items-center justify-center rounded-lg"
      :class="
        failed
          ? 'bg-rose-500/10 text-rose-400'
          : transfer.direction === 'receive'
            ? 'bg-accent/10 text-accent'
            : 'bg-glow/10 text-indigo-300'
      "
    >
      <FileText v-if="transfer.kind === 'text'" class="size-4" />
      <component :is="icon" v-else class="size-4" />
    </span>
    <span class="min-w-0 flex-1">
      <span
        class="block truncate text-sm"
        :class="failed ? 'text-slate-500 line-through' : 'text-slate-300'"
      >
        {{ title }}
      </span>
    </span>
    <span class="shrink-0 text-xs tabular-nums text-slate-600">
      {{ formatBytes(transfer.bytes) }}
    </span>
    <span class="shrink-0 text-xs text-slate-600">{{ ago }}</span>
    <button
      type="button"
      class="rounded p-1 text-slate-700 opacity-0 transition group-hover:opacity-100 hover:text-slate-400"
      :title="t('transfer.remove')"
      @click="removeTransfer(transfer.id)"
    >
      ✕
    </button>
  </div>
</template>

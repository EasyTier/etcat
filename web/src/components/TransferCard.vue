<script setup lang="ts">
import { formatBytes, formatSpeed, transferSpeed } from "@/lib/format";
import { useI18n } from "@/lib/i18n";
import { computed, onUnmounted, ref } from "vue";
import {
  removeTransfer,
  saveReceivedFile,
  type Transfer,
} from "@/lib/transfers";
import {
  CheckCircle2,
  Copy,
  Download,
  Loader2,
  RotateCcw,
  X,
  XCircle,
} from "lucide-vue-next";

const props = defineProps<{ transfer: Transfer }>();
const { t } = useI18n();

// Tick once per second so speed readouts stay fresh during a transfer.
const now = ref(Date.now());
const ticker = setInterval(() => {
  now.value = Date.now();
}, 1000);
onUnmounted(() => clearInterval(ticker));

const active = computed(
  () =>
    props.transfer.status === "connecting" ||
    props.transfer.status === "transferring" ||
    props.transfer.status === "confirming",
);

const speed = computed(() =>
  props.transfer.status === "transferring"
    ? transferSpeed(props.transfer.bytes, props.transfer.startedAt)
    : 0,
);

const progress = computed(() => {
  if (props.transfer.size === null || props.transfer.size === 0) return null;
  return Math.min(1, props.transfer.bytes / props.transfer.size);
});

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

const statusLabel = computed(() => {
  switch (props.transfer.status) {
    case "connecting":
      return props.transfer.direction === "send"
        ? t("transfer.connecting")
        : t("transfer.transferring");
    case "transferring":
      return speed.value > 0
        ? `${t("transfer.transferring")} ${formatSpeed(speed.value)}`
        : t("transfer.transferring");
    case "confirming":
      return t("transfer.confirming");
    case "done":
      return t("transfer.done");
    case "failed":
      return t("transfer.failed");
  }
});

const copiedText = ref(false);
async function copyReceivedText(): Promise<void> {
  if (props.transfer.receivedText === null) return;
  await navigator.clipboard.writeText(props.transfer.receivedText);
  copiedText.value = true;
  setTimeout(() => {
    copiedText.value = false;
  }, 1600);
}

const saving = ref(false);
async function save(): Promise<void> {
  saving.value = true;
  try {
    await saveReceivedFile(props.transfer.id, "etcat-download");
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <div
    class="rounded-xl border border-edge bg-panel/80 p-4 shadow-lg shadow-black/20"
  >
    <div class="flex items-start justify-between gap-3">
      <div class="min-w-0">
        <div class="truncate text-sm font-medium text-slate-100">
          {{ title }}
        </div>
        <div class="mt-0.5 flex items-center gap-2 text-xs text-slate-500">
          <span class="tabular-nums">{{ formatBytes(transfer.bytes) }}</span>
          <template v-if="transfer.size !== null">
            <span aria-hidden="true">/</span>
            <span class="tabular-nums">{{ formatBytes(transfer.size) }}</span>
          </template>
          <span aria-hidden="true">·</span>
          <span>{{ statusLabel }}</span>
        </div>
      </div>
      <div class="flex shrink-0 items-center gap-1">
        <Loader2 v-if="active" class="size-4 animate-spin text-accent" />
        <CheckCircle2
          v-else-if="transfer.status === 'done'"
          class="size-4 text-emerald-400"
        />
        <XCircle v-else class="size-4 text-rose-400" />
        <button
          v-if="!active"
          type="button"
          :title="t('transfer.remove')"
          class="rounded p-1 text-slate-600 transition hover:bg-white/5 hover:text-slate-300"
          @click="removeTransfer(transfer.id)"
        >
          <X class="size-3.5" />
        </button>
      </div>
    </div>

    <div
      v-if="active"
      class="mt-3 h-1.5 overflow-hidden rounded-full bg-edge"
    >
      <div
        v-if="progress !== null"
        class="h-full rounded-full bg-gradient-to-r from-accent to-glow transition-[width] duration-300"
        :style="{ width: `${(progress * 100).toFixed(1)}%` }"
      />
      <div v-else class="progress-indeterminate h-full w-full rounded-full" />
    </div>

    <div v-if="transfer.error !== null" class="mt-2 text-xs text-rose-400">
      {{ transfer.error }}
    </div>

    <div v-if="transfer.status === 'failed' && transfer.retry !== null" class="mt-3">
      <button
        type="button"
        class="inline-flex items-center gap-1.5 rounded-lg border border-edge px-3 py-1.5 text-sm text-slate-300 transition hover:border-accent/50 hover:text-accent"
        @click="transfer.retry?.()"
      >
        <RotateCcw class="size-4" />
        {{ t("transfer.retry") }}
      </button>
    </div>

    <div v-if="transfer.receivedText !== null" class="mt-3">
      <pre class="nice-scroll max-h-48 overflow-auto rounded-lg bg-black/40 p-3 font-mono text-xs text-slate-300 whitespace-pre-wrap">{{ transfer.receivedText }}</pre>
      <button
        type="button"
        class="mt-2 inline-flex items-center gap-1.5 rounded-lg border border-edge px-3 py-1.5 text-sm text-slate-300 transition hover:border-accent/50 hover:text-accent"
        @click="copyReceivedText"
      >
        <Copy class="size-4" />
        {{ copiedText ? t("transfer.textCopied") : t("transfer.copyText") }}
      </button>
    </div>

    <div
      v-if="transfer.direction === 'receive' && transfer.kind === 'file' && transfer.status === 'done'"
      class="mt-3"
    >
      <button
        type="button"
        :disabled="saving"
        class="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-void transition hover:bg-cyan-300 disabled:opacity-50"
        @click="save"
      >
        <Download class="size-4" />
        {{ saving ? t("transfer.saving") : `${t("transfer.saveFile")} (${formatBytes(transfer.bytes)})` }}
      </button>
    </div>
  </div>
</template>

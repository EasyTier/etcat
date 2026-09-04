<script setup lang="ts">
import { formatBytes, formatSpeed, transferSpeed } from "@/lib/format";
import { computed, onUnmounted, ref } from "vue";
import {
  receiveAsFile,
  receiveAsText,
  type Transfer,
} from "@/lib/transfers";
import {
  ArrowDownToLine,
  CheckCircle2,
  Copy,
  FileText,
  Loader2,
  XCircle,
} from "lucide-vue-next";

const props = defineProps<{ transfer: Transfer }>();

// Tick once per second so speed readouts stay fresh during a transfer.
const now = ref(Date.now());
const ticker = setInterval(() => {
  now.value = Date.now();
}, 1000);
onUnmounted(() => clearInterval(ticker));

const speed = computed(() =>
  props.transfer.status === "transferring"
    ? transferSpeed(props.transfer.bytes, props.transfer.startedAt)
    : 0,
);

const progress = computed(() => {
  if (props.transfer.size === null || props.transfer.size === 0) return null;
  return Math.min(1, props.transfer.bytes / props.transfer.size);
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

const statusLabel = computed(() => {
  switch (props.transfer.status) {
    case "connecting":
      return props.transfer.direction === "send"
        ? "Connecting to receiver…"
        : "Incoming connection…";
    case "transferring":
      return speed.value > 0
        ? `${formatSpeed(speed.value)}`
        : "Transferring…";
    case "confirming":
      return "Waiting for receiver confirmation…";
    case "awaiting-choice":
      return "Incoming payload — choose what to do";
    case "done":
      return "Done";
    case "failed":
      return "Failed";
  }
});

const title = computed(() => {
  if (props.transfer.name !== null) return props.transfer.name;
  return props.transfer.direction === "send" ? "Text payload" : "Incoming payload";
});

function saveFile(): void {
  const suggested = `etcat-${new Date().toISOString().replaceAll(/[:.]/g, "-")}`;
  void receiveAsFile(props.transfer.id, suggested);
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
          <span>{{ transfer.direction === "send" ? "Sending" : "Receiving" }}</span>
          <span aria-hidden="true">·</span>
          <span class="tabular-nums">{{ formatBytes(transfer.bytes) }}</span>
          <template v-if="transfer.size !== null">
            <span aria-hidden="true">/</span>
            <span class="tabular-nums">{{ formatBytes(transfer.size) }}</span>
          </template>
        </div>
      </div>
      <Loader2
        v-if="transfer.status === 'connecting' || transfer.status === 'transferring' || transfer.status === 'confirming'"
        class="size-4 shrink-0 animate-spin text-accent"
      />
      <CheckCircle2 v-else-if="transfer.status === 'done'" class="size-4 shrink-0 text-emerald-400" />
      <XCircle v-else-if="transfer.status === 'failed'" class="size-4 shrink-0 text-rose-400" />
      <ArrowDownToLine v-else class="size-4 shrink-0 text-accent" />
    </div>

    <div
      v-if="transfer.status === 'transferring' || transfer.status === 'confirming' || transfer.status === 'connecting'"
      class="mt-3 h-1.5 overflow-hidden rounded-full bg-edge"
    >
      <div
        v-if="progress !== null"
        class="h-full rounded-full bg-gradient-to-r from-accent to-glow transition-[width] duration-300"
        :style="{ width: `${(progress * 100).toFixed(1)}%` }"
      />
      <div v-else class="progress-indeterminate h-full w-full rounded-full" />
    </div>

    <div class="mt-2 text-xs text-slate-400">{{ statusLabel }}</div>
    <div v-if="transfer.error !== null" class="mt-1 text-xs text-rose-400">
      {{ transfer.error }}
    </div>

    <div
      v-if="transfer.status === 'awaiting-choice'"
      class="mt-3 flex flex-wrap gap-2"
    >
      <button
        type="button"
        class="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-void transition hover:bg-cyan-300"
        @click="saveFile"
      >
        <ArrowDownToLine class="size-4" />
        Save as file
      </button>
      <button
        type="button"
        class="inline-flex items-center gap-1.5 rounded-lg border border-edge px-3 py-1.5 text-sm text-slate-300 transition hover:border-accent/50 hover:text-accent"
        @click="receiveAsText(transfer.id)"
      >
        <FileText class="size-4" />
        Show as text
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
        {{ copiedText ? "Copied" : "Copy text" }}
      </button>
    </div>

    <div v-if="transfer.downloadUrl !== null" class="mt-3">
      <a
        :href="transfer.downloadUrl"
        :download="transfer.name ?? 'etcat-download'"
        class="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-void transition hover:bg-cyan-300"
      >
        <ArrowDownToLine class="size-4" />
        Download {{ formatBytes(transfer.bytes) }}
      </a>
    </div>
  </div>
</template>

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

const previewKind = computed<"image" | "video" | "audio" | "pdf" | null>(() => {
  const mime = props.transfer.mime;
  if (mime === null) return null;
  if (mime.startsWith("image/")) return "image";
  if (mime.startsWith("video/")) return "video";
  if (mime.startsWith("audio/")) return "audio";
  if (mime === "application/pdf") return "pdf";
  return null;
});

const previewUrl = computed(() => props.transfer.downloadUrl);
const previewOpen = ref(false);
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
  if (props.transfer.kind === "text") return t("transfer.recvTextTitle");
  return props.transfer.name ?? t("transfer.recvFileTitle");
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

// Sentinel errors written by the transfer store carry an i18n key; everything
// else is a raw message.
const displayError = computed(() => {
  const error = props.transfer.error;
  if (error === null) return null;
  if (error === "i18n:transfer.tooLarge") return t("transfer.tooLarge");
  return error;
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
    await saveReceivedFile(props.transfer.id, props.transfer.name ?? "etcat-download");
  } catch (error) {
    // Keep the payload, but surface the failure on the card.
    props.transfer.error =
      error instanceof Error ? error.message : String(error);
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <div class="card-glow animate-rise rounded-2xl p-5">
    <div class="flex items-start justify-between gap-3">
      <div class="min-w-0">
        <div class="truncate text-base font-medium text-slate-100">
          {{ title }}
        </div>
        <div class="mt-1 flex items-center gap-2 text-sm text-slate-500">
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
        <Loader2 v-if="active" class="size-4.5 animate-spin text-accent" />
        <CheckCircle2
          v-else-if="transfer.status === 'done'"
          class="size-4.5 text-emerald-400"
        />
        <XCircle v-else class="size-4.5 text-rose-400" />
        <button
          v-if="!active"
          type="button"
          :title="t('transfer.remove')"
          class="rounded-lg p-1.5 text-slate-600 transition hover:bg-white/5 hover:text-slate-300"
          @click="removeTransfer(transfer.id)"
        >
          <X class="size-4" />
        </button>
      </div>
    </div>

    <div v-if="active" class="mt-4 h-2 overflow-hidden rounded-full bg-edge">
      <div
        v-if="progress !== null"
        class="h-full rounded-full bg-gradient-to-r from-accent to-glow shadow-[0_0_12px_rgb(34_211_238/0.5)] transition-[width] duration-300"
        :style="{ width: `${(progress * 100).toFixed(1)}%` }"
      />
      <div v-else class="progress-indeterminate h-full w-full rounded-full" />
    </div>

    <div v-if="displayError !== null" class="mt-2.5 text-sm text-rose-400">
      {{ displayError }}
    </div>

    <div v-if="transfer.status === 'failed' && transfer.retry !== null" class="mt-4">
      <button type="button" class="btn-ghost" @click="transfer.retry?.()">
        <RotateCcw class="size-4" />
        {{ t("transfer.retry") }}
      </button>
    </div>

    <div v-if="transfer.receivedText !== null" class="mt-4">
      <pre class="nice-scroll max-h-56 overflow-auto rounded-xl bg-black/40 p-4 font-mono text-sm text-slate-300 whitespace-pre-wrap">{{ transfer.receivedText }}</pre>
      <button type="button" class="btn-ghost mt-3" @click="copyReceivedText">
        <Copy class="size-4" />
        {{ copiedText ? t("transfer.textCopied") : t("transfer.copyText") }}
      </button>
    </div>

    <!-- Inline previews for received files -->
    <div
      v-if="transfer.direction === 'receive' && transfer.kind === 'file' && transfer.status === 'done' && previewKind === 'image' && previewUrl !== null"
      class="mt-4"
    >
      <img
        :src="previewUrl"
        :alt="transfer.name ?? 'preview'"
        class="max-h-72 cursor-zoom-in rounded-xl border border-edge object-contain"
        @click="previewOpen = true"
      />
    </div>
    <div
      v-else-if="transfer.direction === 'receive' && transfer.kind === 'file' && transfer.status === 'done' && previewKind === 'video' && previewUrl !== null"
      class="mt-4"
    >
      <video :src="previewUrl" controls class="max-h-72 rounded-xl border border-edge" />
    </div>
    <div
      v-else-if="transfer.direction === 'receive' && transfer.kind === 'file' && transfer.status === 'done' && previewKind === 'audio' && previewUrl !== null"
      class="mt-4"
    >
      <audio :src="previewUrl" controls class="w-full" />
    </div>
    <div
      v-else-if="transfer.direction === 'receive' && transfer.kind === 'file' && transfer.status === 'done' && previewKind === 'pdf' && previewUrl !== null"
      class="mt-4"
    >
      <button type="button" class="btn-ghost" @click="previewOpen = true">
        {{ t("transfer.previewPdf") }}
      </button>
    </div>

    <div
      v-if="transfer.direction === 'receive' && transfer.kind === 'file' && transfer.status === 'done'"
      class="mt-4"
    >
      <button
        type="button"
        :disabled="saving"
        class="btn-primary !h-11 !px-5 !text-sm"
        @click="save"
      >
        <Download class="size-4" />
        {{ saving ? t("transfer.saving") : `${t("transfer.saveFile")} (${formatBytes(transfer.bytes)})` }}
      </button>
    </div>

    <!-- Full-screen image / PDF preview -->
    <Teleport to="body">
      <div
        v-if="previewOpen && previewUrl !== null"
        class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-6 backdrop-blur-sm"
        @click="previewOpen = false"
      >
        <img
          v-if="previewKind === 'image'"
          :src="previewUrl"
          :alt="transfer.name ?? 'preview'"
          class="max-h-full max-w-full rounded-xl object-contain"
          @click.stop
        />
        <iframe
          v-else-if="previewKind === 'pdf'"
          :src="previewUrl"
          class="h-full w-full rounded-xl border border-edge bg-white"
          @click.stop
        />
      </div>
    </Teleport>
  </div>
</template>

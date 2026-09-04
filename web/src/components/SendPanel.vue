<script setup lang="ts">
import { computed, ref } from "vue";
import { FileUp, SendHorizontal, Type, X } from "lucide-vue-next";
import TransferCard from "./TransferCard.vue";
import { formatBytes } from "@/lib/format";
import { useI18n } from "@/lib/i18n";
import { enqueueSend, pendingSend, store } from "@/lib/transfers";
import { useWasm } from "@/lib/wasm";

const wasm = useWasm();
const { t } = useI18n();

const file = ref<File | null>(null);
const text = ref("");
const dragging = ref(false);
const sending = ref(false);
const sendError = ref<string | null>(null);
const fileInput = ref<HTMLInputElement | null>(null);

const outgoing = computed(() =>
  store.transfers.filter((transfer) => transfer.direction === "send"),
);

/** Accepts a bare etc2 token or a pasted share link carrying ?token=. */
const tokenInvalid = computed(() => {
  const value = pendingSend.token.trim();
  if (value.length === 0) return false;
  if (value.startsWith("etc2")) return false;
  try {
    const url = new URL(value);
    return url.searchParams.get("token") === null;
  } catch {
    return true;
  }
});

const canSend = computed(
  () =>
    wasm.status.kind === "ready" &&
    !sending.value &&
    pendingSend.token.trim().length > 0 &&
    !tokenInvalid.value &&
    (file.value !== null || text.value.length > 0),
);

function pickFile(): void {
  fileInput.value?.click();
}

function onFileChange(event: Event): void {
  const input = event.target as HTMLInputElement;
  file.value = input.files?.[0] ?? null;
  input.value = "";
}

function onDrop(event: DragEvent): void {
  dragging.value = false;
  const dropped = event.dataTransfer?.files?.[0];
  if (dropped !== undefined) {
    file.value = dropped;
  }
}

async function send(): Promise<void> {
  sendError.value = null;
  sending.value = true;
  try {
    if (file.value !== null) {
      const payload = file.value;
      file.value = null;
      await enqueueSend(payload.name, "file", payload.size, async (offset, length) => {
        return new Uint8Array(
          await payload.slice(offset, offset + length).arrayBuffer(),
        );
      });
    } else {
      const data = new TextEncoder().encode(text.value);
      text.value = "";
      await enqueueSend(null, "text", data.byteLength, async (offset, length) => {
        return data.subarray(offset, offset + length);
      });
    }
  } catch (error) {
    sendError.value = error instanceof Error ? error.message : String(error);
  } finally {
    sending.value = false;
  }
}
</script>

<template>
  <div class="space-y-4">
    <label class="block text-sm text-slate-400">
      {{ t("send.tokenLabel") }}
      <input
        v-model="pendingSend.token"
        type="text"
        autocomplete="off"
        spellcheck="false"
        :placeholder="t('send.tokenPlaceholder')"
        class="mt-1.5 w-full rounded-lg border bg-black/30 px-3 py-2.5 font-mono text-sm text-slate-200 outline-none transition placeholder:text-slate-600"
        :class="
          tokenInvalid
            ? 'border-rose-400/60 focus:border-rose-400'
            : 'border-edge focus:border-accent/60'
        "
      />
      <span v-if="tokenInvalid" class="mt-1 block text-xs text-rose-400">
        {{ t("send.tokenInvalid") }}
      </span>
    </label>

    <div
      class="relative rounded-xl border-2 border-dashed transition"
      :class="
        dragging
          ? 'border-accent bg-accent/10'
          : 'border-edge bg-panel/60 hover:border-slate-600'
      "
      @dragover.prevent="dragging = true"
      @dragleave.prevent="dragging = false"
      @drop.prevent="onDrop"
    >
      <input
        ref="fileInput"
        type="file"
        class="hidden"
        @change="onFileChange"
      />
      <div v-if="file !== null" class="flex items-center gap-2 px-4 py-4">
        <span
          class="inline-flex min-w-0 items-center gap-2 rounded-lg border border-accent/40 bg-accent/10 px-3 py-2 text-sm text-slate-200"
        >
          <FileUp class="size-4 shrink-0 text-accent" />
          <span class="truncate">{{ file.name }}</span>
          <span class="shrink-0 text-xs text-slate-500">({{ formatBytes(file.size) }})</span>
          <button
            type="button"
            class="shrink-0 rounded p-0.5 text-slate-500 transition hover:bg-white/10 hover:text-slate-200"
            @click="file = null"
          >
            <X class="size-3.5" />
          </button>
        </span>
      </div>
      <button
        v-else
        type="button"
        class="flex w-full flex-col items-center gap-2 px-4 py-8 text-center"
        @click="pickFile"
      >
        <FileUp class="size-8 text-slate-500" />
        <span class="text-sm text-slate-400">{{ t("send.dropHere") }}</span>
      </button>
    </div>

    <div>
      <label class="mb-1.5 flex items-center gap-1.5 text-sm text-slate-400">
        <Type class="size-3.5" />
        {{ file !== null ? t("send.fileSelected") : t("send.orText") }}
      </label>
      <textarea
        v-model="text"
        rows="3"
        :disabled="file !== null"
        :placeholder="t('send.textPlaceholder')"
        class="nice-scroll w-full resize-none rounded-lg border border-edge bg-black/30 px-3 py-2.5 text-sm text-slate-200 outline-none transition placeholder:text-slate-600 focus:border-accent/60 disabled:opacity-40"
      />
    </div>

    <button
      type="button"
      :disabled="!canSend"
      class="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-4 py-3 text-sm font-semibold text-void transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40"
      @click="send"
    >
      <SendHorizontal class="size-4" />
      {{ sending ? t("send.sending") : file !== null ? t("send.sendFile") : t("send.sendText") }}
    </button>

    <div
      v-if="sendError !== null"
      class="rounded-lg border border-rose-400/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300"
    >
      {{ sendError }}
    </div>

    <div v-if="outgoing.length > 0" class="space-y-3">
      <TransferCard
        v-for="transfer in outgoing"
        :key="transfer.id"
        :transfer="transfer"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from "vue";
import { FileUp, SendHorizontal, X } from "lucide-vue-next";
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
const fileInput = ref<HTMLInputElement | null>(null);

const outgoing = computed(() =>
  store.transfers.filter((transfer) => transfer.direction === "send"),
);

const tokenInvalid = computed(() => {
  const value = pendingSend.token.trim();
  if (value.length === 0) return false;
  if (value.startsWith("etc2")) return false;
  try {
    const url = new URL(value);
    const token = url.searchParams.get("token");
    return token === null || !token.startsWith("etc2");
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
  } catch {
    // The transfer card carries the failure; the panel stays quiet.
  } finally {
    sending.value = false;
  }
}
</script>

<template>
  <div class="space-y-5">
    <div>
      <label class="mb-1.5 block text-sm font-medium text-slate-300">
        {{ t("send.tokenLabel") }}
      </label>
      <input
        v-model="pendingSend.token"
        type="text"
        autocomplete="off"
        spellcheck="false"
        :placeholder="t('send.tokenPlaceholder')"
        class="w-full rounded-xl border bg-black/30 px-4 py-3 font-mono text-sm text-slate-200 outline-none transition placeholder:text-slate-600"
        :class="
          tokenInvalid
            ? 'border-rose-400/60 focus:border-rose-400'
            : 'border-edge focus:border-accent/60'
        "
      />
      <p v-if="tokenInvalid" class="mt-1.5 text-xs text-rose-400">
        {{ t("send.tokenInvalid") }}
      </p>
    </div>

    <div
      class="relative rounded-2xl border-2 border-dashed transition"
      :class="
        dragging
          ? 'border-accent bg-accent/10'
          : 'border-edge bg-panel/40 hover:border-slate-600'
      "
      @dragover.prevent="dragging = true"
      @dragleave.prevent="dragging = false"
      @drop.prevent="onDrop"
    >
      <input ref="fileInput" type="file" class="hidden" @change="onFileChange" />
      <div v-if="file !== null" class="flex items-center gap-3 p-5">
        <span
          class="inline-flex min-w-0 flex-1 items-center gap-3 rounded-xl border border-accent/40 bg-accent/10 px-4 py-3"
        >
          <FileUp class="size-5 shrink-0 text-accent" />
          <span class="truncate text-sm font-medium text-slate-100">{{ file.name }}</span>
          <span class="shrink-0 text-xs text-slate-500">{{ formatBytes(file.size) }}</span>
          <button
            type="button"
            class="ml-auto shrink-0 rounded-lg p-1.5 text-slate-500 transition hover:bg-white/10 hover:text-slate-200"
            @click="file = null"
          >
            <X class="size-4" />
          </button>
        </span>
      </div>
      <button
        v-else
        type="button"
        class="flex w-full flex-col items-center gap-3 px-6 py-12 text-center"
        @click="pickFile"
      >
        <span
          class="flex size-14 items-center justify-center rounded-2xl bg-gradient-to-br from-accent/20 to-glow/20 text-accent transition group-hover:scale-105"
        >
          <FileUp class="size-6" />
        </span>
        <span class="text-base text-slate-400">{{ t("send.dropHere") }}</span>
      </button>
    </div>

    <div>
      <label class="mb-1.5 block text-sm font-medium text-slate-300">
        {{ file !== null ? t("send.fileSelected") : t("send.orText") }}
      </label>
      <textarea
        v-model="text"
        rows="3"
        :disabled="file !== null"
        :placeholder="t('send.textPlaceholder')"
        class="nice-scroll w-full resize-none rounded-xl border border-edge bg-black/30 px-4 py-3 text-sm text-slate-200 outline-none transition placeholder:text-slate-600 focus:border-accent/60 disabled:opacity-40"
      />
    </div>

    <button
      type="button"
      :disabled="!canSend"
      class="btn-primary w-full"
      @click="send"
    >
      <SendHorizontal class="size-5" />
      {{ sending ? t("send.sending") : file !== null ? t("send.sendFile") : t("send.sendText") }}
    </button>

    <div v-if="outgoing.length > 0" class="space-y-4">
      <TransferCard
        v-for="transfer in outgoing"
        :key="transfer.id"
        :transfer="transfer"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { ArrowDownToLine, SendHorizontal } from "lucide-vue-next";
import { useI18n } from "@/lib/i18n";
import { store } from "@/lib/transfers";

export type TransferMode = "receive" | "send";

const props = defineProps<{ modelValue: TransferMode }>();
const emit = defineEmits<{ (e: "update:modelValue", value: TransferMode): void }>();

const { t } = useI18n();

const incomingTotal = computed(
  () => store.transfers.filter((transfer) => transfer.direction === "receive").length,
);
</script>

<template>
  <div class="grid grid-cols-2 gap-3">
    <button
      type="button"
      class="group relative overflow-hidden rounded-2xl border p-5 text-left transition"
      :class="
        modelValue === 'receive'
          ? 'border-accent/50 bg-accent/10'
          : 'border-edge bg-panel/60 hover:border-slate-600'
      "
      @click="emit('update:modelValue', 'receive')"
    >
      <div
        class="mb-3 inline-flex size-11 items-center justify-center rounded-xl transition"
        :class="
          modelValue === 'receive'
            ? 'bg-gradient-to-br from-accent/30 to-glow/30 text-accent'
            : 'bg-white/5 text-slate-400 group-hover:text-slate-300'
        "
      >
        <ArrowDownToLine class="size-5" />
      </div>
      <div class="text-lg font-semibold" :class="modelValue === 'receive' ? 'text-accent' : 'text-slate-200'">
        {{ t("tab.receive") }}
      </div>
      <div class="mt-0.5 text-sm text-slate-500">{{ t("workspace.receiveTitle") }}</div>
      <span
        v-if="incomingTotal > 0"
        class="absolute top-4 right-4 inline-flex min-w-6 items-center justify-center rounded-full bg-accent px-1.5 py-0.5 text-xs font-bold text-void"
      >
        {{ incomingTotal }}
      </span>
    </button>

    <button
      type="button"
      class="group relative overflow-hidden rounded-2xl border p-5 text-left transition"
      :class="
        modelValue === 'send'
          ? 'border-accent/50 bg-accent/10'
          : 'border-edge bg-panel/60 hover:border-slate-600'
      "
      @click="emit('update:modelValue', 'send')"
    >
      <div
        class="mb-3 inline-flex size-11 items-center justify-center rounded-xl transition"
        :class="
          modelValue === 'send'
            ? 'bg-gradient-to-br from-accent/30 to-glow/30 text-accent'
            : 'bg-white/5 text-slate-400 group-hover:text-slate-300'
        "
      >
        <SendHorizontal class="size-5" />
      </div>
      <div class="text-lg font-semibold" :class="modelValue === 'send' ? 'text-accent' : 'text-slate-200'">
        {{ t("tab.send") }}
      </div>
      <div class="mt-0.5 text-sm text-slate-500">{{ t("workspace.sendHint") }}</div>
    </button>
  </div>
</template>

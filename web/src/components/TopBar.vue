<script setup lang="ts">
import { Languages } from "lucide-vue-next";
import { useI18n } from "@/lib/i18n";
import { store } from "@/lib/transfers";
import { computed } from "vue";

const { locale, setLocale, t } = useI18n();

const statusText = computed(() => {
  switch (store.listener.kind) {
    case "listening":
      return store.listener.relayReady
        ? t("receive.listening")
        : t("receive.connecting");
    case "starting":
      return t("receive.starting");
    case "failed":
      return t("receive.failed");
    default:
      return null;
  }
});

const statusReady = computed(
  () => store.listener.kind === "listening" && store.listener.relayReady,
);
</script>

<template>
  <header
    class="flex h-14 shrink-0 items-center gap-4 border-b border-edge bg-panel/40 px-5 backdrop-blur-xl"
  >
    <span
      class="bg-gradient-to-r from-accent to-glow bg-clip-text font-mono text-lg font-bold tracking-tight text-transparent"
    >
      etcat
    </span>
    <span class="hidden text-xs text-slate-600 sm:inline">{{ t("app.subtitle") }}</span>

    <div class="flex-1" />

    <div
      v-if="statusText !== null"
      class="flex items-center gap-2 rounded-full border border-edge px-3 py-1 text-xs"
      :class="statusReady ? 'text-emerald-300' : 'text-amber-300'"
    >
      <span
        class="pulse-dot inline-block size-1.5 rounded-full"
        :class="store.listener.kind === 'listening' ? 'bg-emerald-400' : 'bg-amber-300'"
      />
      {{ statusText }}
    </div>

    <button
      type="button"
      class="inline-flex items-center gap-1.5 rounded-lg border border-edge px-2.5 py-1.5 text-xs text-slate-400 transition hover:border-accent/50 hover:text-accent"
      @click="setLocale(locale === 'zh' ? 'en' : 'zh')"
    >
      <Languages class="size-3.5" />
      {{ locale === "zh" ? "EN" : "中文" }}
    </button>
  </header>
</template>

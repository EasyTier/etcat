<script setup lang="ts">
import { Check, Copy, Link2 } from "lucide-vue-next";
import { computed, ref, watch } from "vue";
import QRCode from "qrcode";
import { useI18n } from "@/lib/i18n";
import { store } from "@/lib/transfers";

const { t } = useI18n();

const copied = ref<"token" | "link" | null>(null);
let resetTimer: ReturnType<typeof setTimeout> | undefined;

const token = computed(() =>
  store.listener.kind === "listening" ? store.listener.token : null,
);

const shareLink = computed(() => {
  if (token.value === null) return null;
  const url = new URL(window.location.href);
  url.search = `?token=${encodeURIComponent(token.value)}`;
  return url.toString();
});

const qrDataUrl = ref<string | null>(null);
watch(
  shareLink,
  async (link) => {
    if (link === null) {
      qrDataUrl.value = null;
      return;
    }
    qrDataUrl.value = await QRCode.toDataURL(link, {
      margin: 1,
      width: 240,
      color: { dark: "#e2f6fc", light: "#00000000" },
    }).catch(() => null);
  },
  { immediate: true },
);

async function copy(which: "token" | "link"): Promise<void> {
  const value = which === "token" ? token.value : shareLink.value;
  if (value === null) return;
  await navigator.clipboard.writeText(value);
  copied.value = which;
  clearTimeout(resetTimer);
  resetTimer = setTimeout(() => {
    copied.value = null;
  }, 1600);
}
</script>

<template>
  <div v-if="token !== null" class="card-glow animate-rise rounded-2xl p-5">
    <div class="flex items-center gap-2 text-base font-medium text-accent">
      <Link2 class="size-4.5" />
      {{ t("token.title") }}
    </div>

    <div class="mt-4 flex flex-wrap items-start gap-5">
      <div class="min-w-0 flex-1">
        <div class="flex flex-wrap gap-2.5">
          <button
            type="button"
            class="btn-primary !h-11 !px-5 !text-sm"
            @click="copy('link')"
          >
            <Check v-if="copied === 'link'" class="size-4" />
            <Link2 v-else class="size-4" />
            {{ copied === "link" ? t("token.copied") : t("token.copyLink") }}
          </button>
          <button
            type="button"
            class="btn-ghost"
            @click="copy('token')"
          >
            <Check v-if="copied === 'token'" class="size-4" />
            <Copy v-else class="size-4" />
            {{ copied === "token" ? t("token.copied") : t("token.copyToken") }}
          </button>
        </div>

        <code class="token-text mt-4 block rounded-xl bg-black/40 p-3.5 font-mono text-xs leading-relaxed break-all text-cyan-100/70">
          {{ token }}
        </code>
        <p class="mt-2.5 text-xs text-slate-500">
          {{ t("token.cliHint") }}
          <code class="font-mono text-slate-400">etcat &lt;token&gt; &lt; file</code>
        </p>
      </div>

      <div v-if="qrDataUrl !== null" class="shrink-0">
        <img
          :src="qrDataUrl"
          alt="Share link QR code"
          class="size-32 rounded-xl"
        />
      </div>
    </div>
  </div>
</template>

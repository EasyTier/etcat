<script setup lang="ts">
import { Check, Copy, Link2 } from "lucide-vue-next";
import { computed, ref } from "vue";
import { store } from "@/lib/transfers";

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
  <div
    v-if="token !== null"
    class="rounded-xl border border-accent/25 bg-accent/5 p-4"
  >
    <div class="mb-2 flex items-center gap-2 text-sm font-medium text-accent">
      <Link2 class="size-4" />
      Share this token with the sender
    </div>
    <code class="token-text block rounded-lg bg-black/40 p-3 font-mono text-xs leading-relaxed text-cyan-100">
      {{ token }}
    </code>
    <div class="mt-3 flex flex-wrap gap-2">
      <button
        type="button"
        class="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-void transition hover:bg-cyan-300"
        @click="copy('token')"
      >
        <Check v-if="copied === 'token'" class="size-4" />
        <Copy v-else class="size-4" />
        {{ copied === "token" ? "Copied" : "Copy token" }}
      </button>
      <button
        type="button"
        class="inline-flex items-center gap-1.5 rounded-lg border border-edge px-3 py-1.5 text-sm text-slate-300 transition hover:border-accent/50 hover:text-accent"
        @click="copy('link')"
      >
        <Check v-if="copied === 'link'" class="size-4" />
        <Link2 v-else class="size-4" />
        {{ copied === "link" ? "Copied" : "Copy share link" }}
      </button>
    </div>
    <p class="mt-2 text-xs text-slate-500">
      The sender can paste the token here, run
      <code class="font-mono text-slate-400">etcat &lt;token&gt; &lt; file</code>,
      or open the share link directly.
    </p>
  </div>
</template>

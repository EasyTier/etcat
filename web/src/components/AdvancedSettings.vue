<script setup lang="ts">
import { ChevronDown } from "lucide-vue-next";
import {
  AccordionContent,
  AccordionHeader,
  AccordionItem,
  AccordionRoot,
  AccordionTrigger,
} from "reka-ui";
import { useI18n } from "@/lib/i18n";
import { settings } from "@/lib/settings";

defineProps<{ bare?: boolean }>();
const { t } = useI18n();
</script>

<template>
  <div v-if="bare" class="space-y-4">
    <label class="block text-xs text-slate-500">
      {{ t("advanced.relayUrl") }}
      <input
        v-model="settings.relayUrl"
        type="text"
        inputmode="url"
        spellcheck="false"
        class="mt-1.5 w-full rounded-xl border border-edge bg-black/30 px-3 py-2.5 font-mono text-sm text-slate-200 outline-none transition focus:border-accent/60"
      />
    </label>
    <label class="block text-xs text-slate-500">
      {{ t("advanced.relayKey") }}
      <input
        v-model="settings.relayKey"
        type="text"
        autocomplete="off"
        spellcheck="false"
        :placeholder="t('advanced.relayKeyPlaceholder')"
        class="mt-1.5 w-full rounded-xl border border-edge bg-black/30 px-3 py-2.5 font-mono text-sm text-slate-200 outline-none transition focus:border-accent/60"
      />
    </label>
    <label class="flex items-start gap-2 text-xs text-slate-500">
      <input
        v-model="settings.persistListenerKey"
        type="checkbox"
        class="mt-0.5 accent-cyan-400"
      />
      <span>
        {{ t("advanced.persist") }}
        <span class="block text-slate-600">{{ t("advanced.persistHint") }}</span>
      </span>
    </label>
  </div>

  <AccordionRoot v-else type="single" collapsible>
    <AccordionItem value="advanced" class="rounded-xl border border-edge bg-panel/60">
      <AccordionHeader>
        <AccordionTrigger
          class="group flex w-full items-center justify-between px-4 py-3 text-sm text-slate-400 transition hover:text-slate-200"
        >
          {{ t("advanced.title") }}
          <ChevronDown
            class="size-4 transition-transform duration-200 group-data-[state=open]:rotate-180"
          />
        </AccordionTrigger>
      </AccordionHeader>
      <AccordionContent class="px-4 pb-4">
        <div class="space-y-4">
          <label class="block text-xs text-slate-500">
            {{ t("advanced.relayUrl") }}
            <input
              v-model="settings.relayUrl"
              type="text"
              inputmode="url"
              spellcheck="false"
              class="mt-1.5 w-full rounded-xl border border-edge bg-black/30 px-3 py-2.5 font-mono text-sm text-slate-200 outline-none transition focus:border-accent/60"
            />
          </label>
          <label class="block text-xs text-slate-500">
            {{ t("advanced.relayKey") }}
            <input
              v-model="settings.relayKey"
              type="text"
              autocomplete="off"
              spellcheck="false"
              :placeholder="t('advanced.relayKeyPlaceholder')"
              class="mt-1.5 w-full rounded-xl border border-edge bg-black/30 px-3 py-2.5 font-mono text-sm text-slate-200 outline-none transition focus:border-accent/60"
            />
          </label>
          <label class="flex items-start gap-2 text-xs text-slate-500">
            <input
              v-model="settings.persistListenerKey"
              type="checkbox"
              class="mt-0.5 accent-cyan-400"
            />
            <span>
              {{ t("advanced.persist") }}
              <span class="block text-slate-600">{{ t("advanced.persistHint") }}</span>
            </span>
          </label>
        </div>
      </AccordionContent>
    </AccordionItem>
  </AccordionRoot>
</template>

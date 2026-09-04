<script setup lang="ts">
import { ChevronDown } from "lucide-vue-next";
import {
  AccordionContent,
  AccordionHeader,
  AccordionItem,
  AccordionRoot,
  AccordionTrigger,
} from "reka-ui";
import { settings } from "@/lib/settings";
</script>

<template>
  <AccordionRoot type="single" collapsible>
    <AccordionItem
      value="advanced"
      class="rounded-xl border border-edge bg-panel/60"
    >
      <AccordionHeader>
        <AccordionTrigger
          class="group flex w-full items-center justify-between px-4 py-3 text-sm text-slate-400 transition hover:text-slate-200"
        >
          Advanced relay settings
          <ChevronDown
            class="size-4 transition-transform duration-200 group-data-[state=open]:rotate-180"
          />
        </AccordionTrigger>
      </AccordionHeader>
      <AccordionContent class="space-y-3 px-4 pb-4">
        <label class="block text-xs text-slate-500">
          EasyTier WebSocket relay
          <input
            v-model="settings.relayUrl"
            type="text"
            inputmode="url"
            spellcheck="false"
            class="mt-1 w-full rounded-lg border border-edge bg-black/30 px-3 py-2 font-mono text-sm text-slate-200 outline-none transition focus:border-accent/60"
          />
        </label>
        <label class="block text-xs text-slate-500">
          Relay public key (optional identity pin, base64)
          <input
            v-model="settings.relayKey"
            type="text"
            autocomplete="off"
            spellcheck="false"
            placeholder="optional"
            class="mt-1 w-full rounded-lg border border-edge bg-black/30 px-3 py-2 font-mono text-sm text-slate-200 outline-none transition focus:border-accent/60"
          />
        </label>
        <label class="flex items-start gap-2 text-xs text-slate-500">
          <input
            v-model="settings.persistListenerKey"
            type="checkbox"
            class="mt-0.5 accent-cyan-400"
          />
          <span>
            Reuse a persistent address
            <span class="block text-slate-600">
              Stores the private listener key in this browser
            </span>
          </span>
        </label>
      </AccordionContent>
    </AccordionItem>
  </AccordionRoot>
</template>

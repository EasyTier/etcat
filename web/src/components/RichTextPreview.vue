<script setup lang="ts">
import { computed, ref } from "vue";
import { Copy } from "lucide-vue-next";
import { useI18n } from "@/lib/i18n";
import type { Transfer } from "@/lib/transfers";

const props = defineProps<{ transfer: Transfer }>();
const { t } = useI18n();

const format = computed(() => {
  switch (props.transfer.mime) {
    case "text/markdown":
      return "markdown";
    case "application/json":
      return "json";
    case "text/csv":
      return "csv";
    case "image/svg+xml":
      return "svg";
    default:
      return "plain";
  }
});

const text = computed(() => props.transfer.receivedText ?? "");

// --- JSON -------------------------------------------------------------------
const jsonFormatted = computed(() => {
  if (format.value !== "json") return null;
  try {
    return JSON.stringify(JSON.parse(text.value), null, 2);
  } catch {
    return null;
  }
});

// --- CSV --------------------------------------------------------------------
interface CsvTable {
  header: string[];
  rows: string[][];
}

const csvTable = computed<CsvTable | null>(() => {
  if (format.value !== "csv") return null;
  const lines = text.value.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length === 0) return null;
  const parseRow = (line: string): string[] => {
    const cells: string[] = [];
    let current = "";
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (inQuotes) {
        if (c === '"' && line[i + 1] === '"') {
          current += '"';
          i += 1;
        } else if (c === '"') {
          inQuotes = false;
        } else {
          current += c;
        }
      } else if (c === '"') {
        inQuotes = true;
      } else if (c === ",") {
        cells.push(current);
        current = "";
      } else {
        current += c;
      }
    }
    cells.push(current);
    return cells;
  };
  return { header: parseRow(lines[0]!), rows: lines.slice(1).map(parseRow) };
});

// --- Markdown (lightweight, escaped first) -----------------------------------
function escapeHtml(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderMarkdown(src: string): string {
  let html = escapeHtml(src);
  // fenced code blocks
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_m, _lang, code) => {
    return `<pre class="md-code">${code.replace(/\n$/, "")}</pre>`;
  });
  // inline code
  html = html.replace(/`([^`\n]+)`/g, '<code class="md-inline">$1</code>');
  // headings
  html = html.replace(/^###### (.+)$/gm, '<h6 class="md-h">$1</h6>');
  html = html.replace(/^##### (.+)$/gm, '<h5 class="md-h">$1</h5>');
  html = html.replace(/^#### (.+)$/gm, '<h4 class="md-h">$1</h4>');
  html = html.replace(/^### (.+)$/gm, '<h3 class="md-h">$1</h3>');
  html = html.replace(/^## (.+)$/gm, '<h2 class="md-h">$1</h2>');
  html = html.replace(/^# (.+)$/gm, '<h1 class="md-h">$1</h1>');
  // bold / italic
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*([^*\n]+)\*/g, "<em>$1</em>");
  // links
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_m, label, url) => {
    const safe = escapeHtml(String(url));
    if (/^javascript:/i.test(String(url).trim())) return label;
    return `<a href="${safe}" target="_blank" rel="noopener" class="md-link">${label}</a>`;
  });
  // line breaks
  html = html.replace(/\n/g, "<br>");
  return html;
}

const markdownHtml = computed(() =>
  format.value === "markdown" ? renderMarkdown(text.value) : null,
);

// --- SVG ---------------------------------------------------------------------
const svgUrl = computed(() =>
  format.value === "svg"
    ? URL.createObjectURL(new Blob([text.value], { type: "image/svg+xml" }))
    : null,
);

const copied = ref(false);
async function copyText(): Promise<void> {
  await navigator.clipboard.writeText(text.value);
  copied.value = true;
  setTimeout(() => {
    copied.value = false;
  }, 1600);
}
</script>

<template>
  <div>
    <img
      v-if="format === 'svg' && svgUrl !== null"
      :src="svgUrl"
      :alt="transfer.name ?? 'SVG preview'"
      class="max-h-72 rounded-xl border border-edge bg-white/90 object-contain p-2"
    />

    <pre
      v-else-if="format === 'json' && jsonFormatted !== null"
      class="nice-scroll max-h-56 overflow-auto rounded-xl bg-black/40 p-4 font-mono text-sm text-emerald-200/90 whitespace-pre"
    >{{ jsonFormatted }}</pre>

    <div
      v-else-if="format === 'csv' && csvTable !== null"
      class="nice-scroll max-h-56 overflow-auto rounded-xl border border-edge"
    >
      <table class="w-full text-left text-xs">
        <thead>
          <tr>
            <th
              v-for="(cell, i) in csvTable.header"
              :key="i"
              class="border-b border-edge bg-white/5 px-3 py-2 font-medium text-slate-300"
            >
              {{ cell }}
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(row, i) in csvTable.rows" :key="i" class="border-b border-edge/50 last:border-0">
            <td v-for="(cell, j) in row" :key="j" class="px-3 py-1.5 text-slate-400">
              {{ cell }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div
      v-else-if="format === 'markdown' && markdownHtml !== null"
      class="md-body nice-scroll max-h-56 overflow-auto rounded-xl bg-black/40 p-4 text-sm text-slate-300"
      v-html="markdownHtml"
    />

    <pre
      v-else
      class="nice-scroll max-h-56 overflow-auto rounded-xl bg-black/40 p-4 font-mono text-sm text-slate-300 whitespace-pre-wrap"
    >{{ text }}</pre>

    <button type="button" class="btn-ghost mt-3" @click="copyText">
      <Copy class="size-4" />
      {{ copied ? t("transfer.textCopied") : t("transfer.copyText") }}
    </button>
  </div>
</template>

<style scoped>
.md-body :deep(.md-h) {
  margin: 0.6em 0 0.3em;
  font-weight: 600;
  color: #e2e8f0;
}
.md-body :deep(h1.md-h) { font-size: 1.25rem; }
.md-body :deep(h2.md-h) { font-size: 1.15rem; }
.md-body :deep(h3.md-h) { font-size: 1.05rem; }
.md-body :deep(.md-code) {
  margin: 0.5em 0;
  padding: 0.6em 0.8em;
  border-radius: 0.5rem;
  background: rgb(0 0 0 / 0.5);
  font-family: "JetBrains Mono", ui-monospace, monospace;
  font-size: 0.8em;
  white-space: pre-wrap;
}
.md-body :deep(.md-inline) {
  padding: 0.1em 0.35em;
  border-radius: 0.3rem;
  background: rgb(0 0 0 / 0.5);
  font-family: "JetBrains Mono", ui-monospace, monospace;
  font-size: 0.85em;
}
.md-body :deep(.md-link) {
  color: #22d3ee;
  text-decoration: underline;
  text-underline-offset: 2px;
}
</style>

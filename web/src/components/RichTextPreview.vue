<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from "vue";
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

// --- JSON ---------------------------------------------------------------------
const jsonFormatted = computed(() => {
  if (format.value !== "json") return null;
  try {
    return JSON.stringify(JSON.parse(text.value.trim()), null, 2);
  } catch {
    return null;
  }
});

// --- CSV ----------------------------------------------------------------------
// Preview is capped; the full payload stays available via the save action.
const CSV_MAX_ROWS = 200;
const CSV_MAX_COLS = 64;

interface CsvTable {
  header: string[];
  rows: string[][];
  truncated: boolean;
}

const csvTable = computed<CsvTable | null>(() => {
  if (format.value !== "csv") return null;
  const src = text.value;
  // Parse records from the complete string so quoted fields may span lines.
  const rows: string[][] = [];
  let field = "";
  let row: string[] = [];
  let inQuotes = false;
  let i = 0;
  const pushField = () => {
    row.push(field);
    field = "";
  };
  const pushRow = () => {
    if (row.length > 1 || row[0] !== undefined && row[0].trim().length > 0) {
      rows.push(row);
    }
    row = [];
  };
  while (i < src.length && rows.length <= CSV_MAX_ROWS) {
    const c = src[i]!;
    if (inQuotes) {
      if (c === '"' && src[i + 1] === '"') {
        field += '"';
        i += 2;
      } else if (c === '"') {
        inQuotes = false;
        i += 1;
      } else {
        field += c;
        i += 1;
      }
    } else if (c === '"') {
      inQuotes = true;
      i += 1;
    } else if (c === ",") {
      pushField();
      i += 1;
    } else if (c === "\n" || c === "\r") {
      pushField();
      pushRow();
      if (c === "\r" && src[i + 1] === "\n") i += 1;
      i += 1;
    } else {
      field += c;
      i += 1;
    }
  }
  pushField();
  pushRow();
  const truncatedByRows = i < src.length;
  if (rows.length === 0) return null;
  const header = rows[0]!.slice(0, CSV_MAX_COLS);
  return {
    header,
    rows: rows.slice(1).map((r) => r.slice(0, CSV_MAX_COLS)),
    truncated: truncatedByRows || rows.some((r) => r.length > CSV_MAX_COLS),
  };
});

// --- Markdown (lightweight) -----------------------------------------------------
function escapeHtml(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderMarkdown(src: string): string {
  // Stash code spans and links as placeholders before escaping so later
  // substitutions never reach inside them, and link URLs are validated and
  // escaped exactly once from the raw source.
  const stash: string[] = [];
  const keep = (html: string): string => `@@MD${stash.push(html) - 1}@@`;

  let work = src;
  work = work.replace(/```(\w*)\r?\n([\s\S]*?)```/g, (_m, _lang, code) =>
    keep(`<pre class="md-code">${escapeHtml(String(code).replace(/\r?\n$/, ""))}</pre>`),
  );
  work = work.replace(/`([^`\n]+)`/g, (_m, code) =>
    keep(`<code class="md-inline">${escapeHtml(String(code))}</code>`),
  );
  work = work.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_m, label, url) => {
    // Browsers strip ASCII whitespace from URLs when parsing; do the same
    // before scheme validation so java\tscript: cannot smuggle through.
    const cleaned = String(url).replace(/[\t\n\r ]+/g, "");
    const scheme = cleaned.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/)?.[1]?.toLowerCase();
    if (scheme !== undefined && !["http", "https", "mailto"].includes(scheme)) {
      return keep(escapeHtml(String(label)));
    }
    return keep(
      `<a href="${escapeHtml(cleaned)}" target="_blank" rel="noopener" class="md-link">${escapeHtml(String(label))}</a>`,
    );
  });

  let html = escapeHtml(work);
  html = html.replace(/^###### (.+)$/gm, '<h6 class="md-h">$1</h6>');
  html = html.replace(/^##### (.+)$/gm, '<h5 class="md-h">$1</h5>');
  html = html.replace(/^#### (.+)$/gm, '<h4 class="md-h">$1</h4>');
  html = html.replace(/^### (.+)$/gm, '<h3 class="md-h">$1</h3>');
  html = html.replace(/^## (.+)$/gm, '<h2 class="md-h">$1</h2>');
  html = html.replace(/^# (.+)$/gm, '<h1 class="md-h">$1</h1>');
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*([^*\n]+)\*/g, "<em>$1</em>");
  html = html.replace(/\n/g, "<br>");
  return html.replace(/@@MD(\d+)@@/g, (_m, i) => stash[Number(i)] ?? "");
}

const markdownHtml = computed(() =>
  format.value === "markdown" ? renderMarkdown(text.value) : null,
);

// --- SVG ------------------------------------------------------------------------
// Manage the blob URL lifecycle explicitly so previews don't leak.
const svgUrl = ref<string | null>(null);
watch(
  [format, text],
  ([fmt, content]) => {
    if (svgUrl.value !== null) {
      URL.revokeObjectURL(svgUrl.value);
      svgUrl.value = null;
    }
    if (fmt === "svg") {
      svgUrl.value = URL.createObjectURL(new Blob([content], { type: "image/svg+xml" }));
    }
  },
  { immediate: true },
);
onUnmounted(() => {
  if (svgUrl.value !== null) {
    URL.revokeObjectURL(svgUrl.value);
  }
});

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
      <p v-if="csvTable.truncated" class="px-3 py-2 text-xs text-slate-600">
        {{ t("transfer.previewTruncated") }}
      </p>
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

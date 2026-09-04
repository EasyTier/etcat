import tailwindcss from "@tailwindcss/vite";
import vue from "@vitejs/plugin-vue";
import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      "@runtime": fileURLToPath(new URL("./vendor/runtime", import.meta.url)),
    },
  },
  build: {
    // The EasyTier core is a 3.6 MB wasm fetched separately; keep the JS
    // warning threshold focused on our own bundle.
    chunkSizeWarningLimit: 600,
  },
});

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  server: {
    port: process.env.PORT ? Number(process.env.PORT) : 5173,
    proxy: { "/api": { target: process.env.ASM_API_URL ?? "http://localhost:8000", changeOrigin: false } },
  },
  build: { sourcemap: false, chunkSizeWarningLimit: 900 },
});

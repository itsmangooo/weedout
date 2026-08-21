import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const backend = "http://localhost:8000";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: backend,
      },
      "/healthz": {
        target: backend,
      },
      "/events": {
        target: backend,
      },
      // Authentication UI remains server-rendered. Proxying the existing
      // login route lets the Phase 2 guard hand off without CORS or a second
      // backend origin, and its redirect returns to the React proof route.
      "/login": {
        target: backend,
      },
      // The canonical `/dashboard` stays with Vite during local development.
      // Only its temporary rollback URL and the other legacy flows proxy to
      // Python, matching the production route-ownership boundary.
      "/dashboard/legacy": {
        target: backend,
      },
      "/alerts": {
        target: backend,
      },
      "/targets": {
        target: backend,
      },
      "/settings": {
        target: backend,
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.js",
    css: true,
    restoreMocks: true,
  },
});

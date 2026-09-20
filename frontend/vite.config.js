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
      // Only what Python owns. Every page route is React now, so proxying one
      // here would serve the built shell from the container instead of the
      // module Vite is watching.
      "/api": { target: backend },
      "/healthz": { target: backend },
      "/events": { target: backend },
      "/webhooks": { target: backend },
      "/install.sh": { target: backend },
      "/install.ps1": { target: backend },
      // The pre-paint theme script and the favicon live with the backend's
      // static files, and index.html asks for them by absolute path.
      "/static": { target: backend },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.js",
    css: true,
    restoreMocks: true,
    // Route modules are intentionally lazy and transform on demand. Running
    // every jsdom file in parallel made those imports miss assertion timeouts
    // under ordinary Windows CI load, even though each file passed alone.
    // Serial files keep the default `npm test -- --run` contract deterministic.
    fileParallelism: false,
    testTimeout: 10_000,
  },
});

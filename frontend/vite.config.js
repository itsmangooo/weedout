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
  },
});

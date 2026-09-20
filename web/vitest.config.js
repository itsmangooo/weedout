import { defineConfig } from "vitest/config";

export default defineConfig({
  esbuild: { jsx: "automatic" },
  test: {
    environment: "jsdom",
    setupFiles: "./src/ui/test/setup.js",
    css: true,
    restoreMocks: true,
    fileParallelism: false,
    testTimeout: 10_000,
    include: ["src/ui/**/*.test.{js,jsx}"],
  },
});

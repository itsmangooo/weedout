import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";

export default defineConfig([
  ...nextVitals,
  ...nextTypescript,
  // The migrated JSX shell remains covered by the original frontend ESLint
  // configuration until its files are converted to TypeScript incrementally.
  globalIgnores([".next/**", "next-env.d.ts", "src/ui/**"]),
]);

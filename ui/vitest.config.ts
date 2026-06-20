import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    restoreMocks: true,
    coverage: {
      provider: "v8",
      reporter: ["text", "html"],
      include: ["src/**/*.{ts,tsx}"],
      exclude: [
        "src/main.tsx", "src/**/*.d.ts", "src/types.ts", "src/vite-env.d.ts",
        "src/lib/platform.ts", "src/lib/wasmEngine.ts", "src/lib/recent.ts", "src/wasm/**",
        "src/components/triage/**", "src/components/TopTalkers.tsx",
        "src/components/layout/DashboardGrid.tsx", "src/components/layout/Panel.tsx",
        "src/components/layout/StatTile.tsx", "src/components/layout/TabBar.tsx",
        "src/components/primitives/Chip.tsx",
        "src/test/**", "**/*.test.{ts,tsx}",
      ],
      thresholds: { lines: 80, functions: 80, statements: 80, branches: 70 },
    },
  },
});

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "Geist", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["Geist Mono", "ui-monospace", "SFMono-Regular", "SF Mono", "Menlo", "Consolas", "monospace"],
      },
      colors: {
        bg: "var(--color-bg)",
        surface: "var(--color-surface)",
        "surface-2": "var(--color-surface-2)",
        border: "var(--color-border)",
        grid: "var(--color-grid)",
        sev: {
          critical: "var(--color-sev-critical)",
          high: "var(--color-sev-high)",
          medium: "var(--color-sev-medium)",
          info: "var(--color-sev-info)",
          none: "var(--color-sev-none)",
        },
      },
    },
  },
  plugins: [],
};

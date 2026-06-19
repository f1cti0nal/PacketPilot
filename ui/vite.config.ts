import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Vite 5 + plugin-react 4 is the only valid React-18 pairing.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
});

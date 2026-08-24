import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The published bundle must be entirely self-contained: the Tauri CSP forbids
// any external origin, so nothing may be fetched at runtime.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { target: "safari15", outDir: "dist", emptyOutDir: true },
});

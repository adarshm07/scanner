import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // API_TARGET points the dev server at another backend (e.g. one started on :4001).
      "/api": process.env.API_TARGET ?? "http://localhost:4000",
    },
  },
});

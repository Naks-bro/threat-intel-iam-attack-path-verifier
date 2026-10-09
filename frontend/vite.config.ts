import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const apiPort = Number(process.env.FYP_API_PORT ?? "8765");
if (!Number.isInteger(apiPort) || apiPort < 1024 || apiPort > 65535) {
  throw new Error("FYP_API_PORT must be a non-privileged local port");
}
const apiTarget = `http://127.0.0.1:${apiPort}`;

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/health": apiTarget,
      "/v1": apiTarget,
    },
  },
  preview: {
    proxy: {
      "/health": apiTarget,
      "/v1": apiTarget,
    },
  },
});

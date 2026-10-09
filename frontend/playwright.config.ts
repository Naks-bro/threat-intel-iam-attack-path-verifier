import { defineConfig, devices } from "@playwright/test";

const e2ePort = Number(process.env.FYP_E2E_PORT ?? "5173");
if (!Number.isInteger(e2ePort) || e2ePort < 1024 || e2ePort > 65535) {
  throw new Error("FYP_E2E_PORT must be a non-privileged local port");
}
const baseURL = `http://127.0.0.1:${e2ePort}`;

export default defineConfig({
  testDir: "./e2e",
  expect: { timeout: 20_000 },
  timeout: 60_000,
  use: {
    ...devices["Desktop Chrome"],
    ...(process.env.FYP_E2E_EDGE === "1" ? { channel: "msedge" as const } : {}),
    baseURL,
  },
  webServer: {
    command: `npm run dev -- --host 127.0.0.1 --port ${e2ePort} --strictPort`,
    url: baseURL,
    reuseExistingServer: !process.env.CI,
  },
});

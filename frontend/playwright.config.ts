import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  expect: { timeout: 20_000 },
  timeout: 60_000,
  use: {
    ...devices["Desktop Chrome"],
    ...(process.env.FYP_E2E_EDGE === "1" ? { channel: "msedge" as const } : {}),
    baseURL: "http://127.0.0.1:5173",
  },
  webServer: {
    command: "npm run dev -- --host 127.0.0.1 --port 5173",
    url: "http://127.0.0.1:5173",
    reuseExistingServer: !process.env.CI,
  },
});

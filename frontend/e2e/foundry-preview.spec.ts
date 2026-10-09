import { expect, test } from "@playwright/test";

test("live offline preview exposes the deterministic dossier without claiming persistence", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Operations overview" })).toBeVisible();
  await expect(page.locator(".preview-label")).toHaveText("OFFLINE PREVIEW");
  await expect(page.getByText("Offline preview", { exact: true }).first()).toBeVisible();
  await page.getByRole("link", { name: "Open rule dossier" }).click();
  await expect(page).toHaveURL(/#\/rules$/);
  await expect(page.getByRole("heading", { level: 1, name: "Rule assurance" })).toBeFocused();
  await expect(page.getByRole("heading", { name: "Scenario review" })).toBeVisible();
  await expect(page.locator(".scenario-list article")).toHaveCount(6);
  await expect(page.locator(".validation-list article")).toHaveCount(14);
  await expect(page.getByText("4 optional tools unavailable", { exact: true })).toBeVisible();
  await expect(page.locator(".validation-list").getByText("This candidate declares no condition key")).toBeVisible();
  await expect(page.getByText("rule_additional_cloud_credentials").first()).toBeVisible();
  await expect(page.getByText(/This candidate is not published or exported/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "Versioned quality report" })).toBeVisible();
  await page.getByText("Report stage metadata · 14 checks").click();
  await expect(page.getByText("Not measured", { exact: true })).toHaveCount(14);
  await expect(page.getByText("foundry-ontology-0.1", { exact: true })).toBeVisible();
  await page.getByText("Report stage metadata · 14 checks").click();
  await page.getByRole("region", { name: "Versioned quality report" }).screenshot({ path: "../artifacts/engine1-quality-report.png" });
  const response = page.waitForResponse((item) => item.url().endsWith("/v1/foundry/runs") && item.request().method() === "POST");
  await page.getByRole("button", { name: "Recompute preview" }).click();
  expect((await response).status()).toBe(200);
  await expect(page.getByText("Preview recomputed")).toBeVisible();
  await expect(page.getByText(/Nothing was stored or published/)).toBeVisible();
  expect(errors).toEqual([]);
});

test("workspace deep links, keyboard navigation, and architecture stay usable at each breakpoint", async ({ page }) => {
  await page.goto("/#/architecture");
  await expect(page.getByRole("heading", { level: 1, name: "System architecture" })).toBeVisible();
  await expect(page.getByRole("figure", { name: "Engine 1 evidence-to-rule architecture" })).toBeVisible();
  await expect(page.getByText("Exact-version human review")).toBeVisible();
  for (const width of [320, 768, 1024, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  }
  await page.getByRole("link", { name: "Source intelligence", exact: true }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: "Source intelligence" })).toBeFocused();
  await expect(page.getByRole("link", { name: "Source intelligence", exact: true })).toHaveAttribute("aria-current", "page");
  await page.goBack();
  await expect(page.getByRole("heading", { level: 1, name: "System architecture" })).toBeVisible();
  await page.reload();
  await expect(page.getByRole("heading", { level: 1, name: "System architecture" })).toBeVisible();
  await page.screenshot({ path: "../artifacts/engine1-architecture-desktop.png", fullPage: true });
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1, name: "Operations overview" })).toBeVisible();
  await page.screenshot({ path: "../artifacts/engine1-operations-desktop.png", fullPage: true });
  for (const route of ["overview", "pipeline", "sources", "primitives", "evidence", "rules", "architecture"]) {
    await page.goto(`/#/${route}`);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    for (const width of [320, 768, 1024, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), `${route} at ${width}px`).toBe(true);
    }
  }
  await page.setViewportSize({ width: 320, height: 900 });
  await page.screenshot({ path: "../artifacts/engine1-architecture-mobile.png", fullPage: true });
});

import { expect, test } from "@playwright/test";

test("local operator records an exact-input scoped revision and reads it after reload", async ({ page }) => {
  const errors: string[] = [];
  const reviewStatuses: number[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("response", (response) => { if (/\/review(?:s|\?)/.test(response.url())) reviewStatuses.push(response.status()); });
  await page.goto("/");
  await page.getByRole("button", { name: "Run evidence pipeline" }).click();
  await expect(page.getByText("Evidence run stored")).toBeVisible();
  await page.getByRole("link", { name: "Rule registry", exact: true }).click();
  await page.getByRole("button", { name: "rule_additional_cloud_credentials" }).click();
  await page.getByLabel("Approval scope").selectOption("synthetic_benchmark");
  await expect(page.getByText("No decision recorded for this scope.")).toBeVisible();
  await page.getByLabel("Non-sensitive review comment").fill("Browser test requests more evidence; not a real human approval.");
  const confirmation = page.getByLabel("I reviewed this exact version and selected scope.");
  await confirmation.focus();
  await page.keyboard.press("Space");
  await page.getByRole("button", { name: "Record scoped decision" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText("Decision recorded. No stable publication or AWS action was performed.")).toBeVisible();
  await expect(page.getByText("revision_requested / ui_test_operator", { exact: true })).toBeVisible();
  await page.reload();
  await page.getByRole("button", { name: "rule_additional_cloud_credentials" }).click();
  await page.getByLabel("Approval scope").selectOption("synthetic_benchmark");
  await expect(page.getByText("revision_requested / ui_test_operator", { exact: true })).toBeVisible();
  for (const width of [320, 768, 1024, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    await expect(page.getByRole("heading", { name: "Exact-input operator review" })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  }
  await page.locator(".review-panel").screenshot({ path: "artifacts/engine1-review-panel.png" });
  expect(errors).toEqual([]);
  expect(reviewStatuses.length).toBeGreaterThan(2);
  expect(reviewStatuses.every((status) => status === 200)).toBeTruthy();
});

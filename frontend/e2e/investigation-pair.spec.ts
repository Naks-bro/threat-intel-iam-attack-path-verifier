import { expect, test } from "@playwright/test";

test("analyst can compare and inspect the two synthetic starting identities", async ({ page }) => {
  await page.goto("/#/investigate");
  await expect(page.getByRole("heading", { name: "Timeline" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Choose a starting identity" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "No identity selected" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Exposed comparator/ })).toContainText("Candidate path");
  await expect(page.getByRole("button", { name: /Control comparator/ })).toContainText("No path for tested rule");
  await expect(page.getByRole("button", { name: "Developer, nexus event, iam:CreateAccessKey" })).toBeVisible();

  await page.getByRole("button", { name: /Exposed comparator/ }).click();
  await expect(page.getByRole("heading", { name: "How the path works" })).toBeVisible();
  await expect(page.getByText("Graph-input digest")).toBeVisible();
  await expect(page.locator(".investigation-facts").getByText(/^sha256:[0-9a-f]{64}$/)).toHaveCount(2);
  await expect(page.getByRole("heading", { name: "Remove this permission edge?" })).toBeVisible();

  await page.getByRole("button", { name: /Control comparator/ }).click();
  await expect(page.getByRole("heading", { name: "What this result does not say" })).toBeVisible();
  await expect(page.getByText(/not a security certificate/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "How the path works" })).toHaveCount(0);
});

test("identity ledger remains usable at a narrow viewport", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 700 });
  await page.goto("/#/investigate");
  await expect(page.getByRole("button", { name: /Control comparator/ })).toBeVisible();
  await page.getByRole("button", { name: /Exposed comparator/ }).click();
  await expect(page.getByText("Graph-input digest")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)).toBe(false);
  await page.getByRole("button", { name: /Control comparator/ }).click();
  await expect(page.getByRole("heading", { name: "What this result does not say" })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  expect(overflow).toBe(false);
});

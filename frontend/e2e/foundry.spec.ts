import { expect, test } from "@playwright/test";

test("pipeline run shows the experimental credential rule", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Operations overview" })).toBeVisible();
  await page.getByRole("button", { name: "Run evidence pipeline" }).click();
  await expect(page.getByText("Evidence run stored")).toBeVisible();
  await page.getByRole("link", { name: "Attack primitives", exact: true }).click();
  await expect(page.getByText("trust_policy_backdoor")).toBeVisible();
  await page.getByRole("link", { name: "Rule registry", exact: true }).click();
  await page.getByRole("button", { name: "rule_additional_cloud_credentials" }).click();
  await expect(page.getByText("Verifier harness")).toBeVisible();
  await expect(page.getByText(/Experimental isolation/)).toBeVisible();
  await expect(page.locator("article").filter({ hasText: "Scenario corpus" })).toContainText("6/6");
});

import { expect, test } from "@playwright/test";

test("pipeline run shows the experimental credential rule", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Threat-to-rule foundry" })).toBeVisible();
  await page.getByRole("button", { name: "Run pipeline" }).click();
  await expect(page.getByText("Stored in PostgreSQL. The rule is experimental.")).toBeVisible();
  await expect(page.getByText("rule_additional_cloud_credentials")).toBeVisible();
  await expect(page.getByText("trust_policy_backdoor")).toBeVisible();
});

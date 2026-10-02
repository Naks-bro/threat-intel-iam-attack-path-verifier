import { expect, test } from "@playwright/test";

test("pipeline run shows the experimental credential rule", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Threat-to-rule foundry" })).toBeVisible();
  await expect(page.getByText("No sources ingested yet.")).toBeVisible();
  await page.getByRole("button", { name: "Run pipeline" }).click();
  await expect(page.getByText("Stored in PostgreSQL. The rule is experimental.")).toBeVisible();
  await expect(page.getByText("trust_policy_backdoor")).toBeVisible();
  await page.getByRole("button", { name: "rule_additional_cloud_credentials" }).click();
  await expect(page.getByText(/Channel experimental/)).toBeVisible();
  await expect(page.getByText("allow-create-access-key")).toBeVisible();
});

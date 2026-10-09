import { expect, test } from "@playwright/test";

test("operator sees disabled source and reviewable scenario outcomes", async ({ page }) => {
  const overview = {
    schema_version: "0.1",
    database: "ok",
    database_detail: "reachable",
    storage: "postgres",
    registry: "ready",
    sources: [
      { source_key: "mitre-attack", authority_tier: 1, source_type: "taxonomy", version_label: "19.2", enabled: true, last_status: "succeeded" },
      { source_key: "aws-threat-technique-catalog", authority_tier: 1, source_type: "threat_catalog", version_label: "not_ingested", enabled: false, last_status: "disabled" },
    ],
    run: { status: "succeeded", fetched_count: 1, created_count: 0, unchanged_count: 1, rejected_count: 0, parser_version: "foundry-pin-parser-0.1" },
    primitives: [],
    relations: [],
    candidates: [{ rule_id: "rule_additional_cloud_credentials", version_id: "version_offline", semantic_hash: "sha256:offline", lifecycle: "experimental", channel: "experimental" }],
  };
  const rule = {
    rule_id: "rule_additional_cloud_credentials",
    version_id: "version_offline",
    semantic_hash: "sha256:offline",
    lifecycle: "experimental",
    rule: { title: "Additional access key", evidence_refs: ["evidence_offline"], limitations: ["Service control policies are not evaluated."] },
    validations: [{ validator_name: "ontology", result: "pass" }, { validator_name: "scenario_corpus", result: "pass" }],
    ai_verification: { provider: "fake", model: "schema-only", verdict: "pass" },
    publication: { channel: "experimental" },
    scenarios: [
      { scenario_id: "target-type-unknown", case_class: "missing_context", expect: "inconclusive", actual: "inconclusive", result: "pass" },
      { scenario_id: "wildcard-action-unsupported", case_class: "adversarial", expect: "inconclusive", actual: "inconclusive", result: "pass" },
    ],
  };
  await page.route("**/v1/foundry/overview", (route) => route.fulfill({ json: overview }));
  await page.route("**/v1/foundry/rules/version_offline", (route) => route.fulfill({ json: rule }));
  await page.route("**/v1/foundry/runs", (route) => route.fulfill({ json: overview }));

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Operations overview" })).toBeVisible();
  await expect(page.getByText("Source integrity").locator("..")).toContainText("1/1");
  await page.getByRole("link", { name: "Source intelligence", exact: true }).click();
  await expect(page.getByText("disabled", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Rule registry", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Scenario review" })).toBeVisible();
  await expect(page.getByText("target-type-unknown")).toBeVisible();
  await expect(page.getByText("evidence_offline")).toBeVisible();
  await page.getByRole("button", { name: "Run evidence pipeline" }).click();
  await expect(page.getByText("Evidence run stored")).toBeVisible();
});

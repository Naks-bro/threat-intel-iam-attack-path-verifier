import { expect, test } from "@playwright/test";

test("exact verifier metadata is inspectable, keyboard accessible and never inferred", async ({ page, context }) => {
  // Contract-shaped UI fixture, not a claim that this browser used PostgreSQL.
  const hash = (digit: string) => `sha256:${digit.repeat(64)}`;
  const record = {
    packet_id: "vpacket_browser", pipeline_run_id: "pipeline_browser", recorded_at: "2026-10-03T00:00:00Z",
    rule_version_id: "version_browser", rule_semantic_hash: hash("1"), evidence_snapshot_hash: hash("2"),
    request_hash: hash("3"), response_hash: hash("4"), provider: "fake", model: "schema-only",
    prompt_version: "verifier-prompt-0.1", ontology_version: "foundry-ontology-0.1", verdict: "needs_review",
    findings: ["A recorded limitation needs review"], citations: ["evidence_browser"],
    evidence: [{ evidence_id: "evidence_browser", source_key: "mitre-attack", source_version: "19.2", content_hash: hash("5") }],
  };
  const overview = {
    database: "ok", database_detail: "reachable", storage: "postgres", registry: "ready",
    sources: [], run: null, primitives: [], relations: [],
    candidates: [{ rule_id: "rule_browser", version_id: "version_browser", semantic_hash: hash("1"), lifecycle: "proposed", channel: "gated" }],
  };
  const rule = {
    rule_id: "rule_browser", version_id: "version_browser", semantic_hash: hash("1"), lifecycle: "proposed",
    rule: { title: "Browser-only review fixture" }, validations: [], scenarios: [], publication: null,
    ai_verification: { provider: "fake", model: "schema-only", verdict: "pass" },
    verifier_record: record as typeof record | null,
  };
  const errors: string[] = [];
  const responseStatuses: number[] = [];
  page.on("pageerror", error => errors.push(error.message));
  page.on("response", response => { if (response.url().includes("/v1/foundry/")) responseStatuses.push(response.status()); });
  await context.route("**/v1/foundry/**", route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/v1/foundry/overview") return route.fulfill({ json: overview });
    if (path === "/v1/foundry/rules/version_browser") return route.fulfill({ json: rule });
    return route.fulfill({ status: 400, json: { detail: "unexpected_fixture_request" } });
  });
  await page.goto("/#/rules");
  const panel = page.getByRole("region", { name: "Recorded verifier input binding" });
  await expect(panel).toBeVisible();
  await expect(page.locator(".assurance-matrix")).toContainText("needs_review");
  const details = panel.locator("summary");
  await details.focus();
  await page.keyboard.press("Enter");
  await expect(panel.getByText("A recorded limitation needs review")).toBeVisible();
  await expect(panel.getByText("mitre-attack · 19.2")).toBeVisible();
  for (const width of [320, 768, 1024, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  }
  await page.screenshot({ path: "../artifacts/engine1-verifier-dossier-desktop.png", fullPage: true });
  rule.verifier_record = { ...record, rule_version_id: "wrong_version" };
  await page.reload();
  await expect(page.getByRole("alert").filter({ hasText: "Verifier record binding mismatch" })).toBeVisible();
  await expect(page.locator(".assurance-matrix")).toContainText("binding mismatch");
  rule.verifier_record = null;
  await page.reload();
  await expect(page.getByText("Exact verifier record unavailable", { exact: true })).toBeVisible();
  expect(errors).toEqual([]);
  expect(responseStatuses.length).toBeGreaterThan(1);
  expect(responseStatuses.every(status => status === 200)).toBe(true);
});

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import * as api from "./foundry-api";
import { qualityFixture } from "./generated/quality-fixture";
import { ReviewPanel, reviewBinding } from "./ReviewPanel";

vi.mock("./foundry-api", async (importOriginal) => ({ ...await importOriginal<typeof api>(), getReviewState: vi.fn(), recordReview: vi.fn() }));
const digest = `sha256:${"1".repeat(64)}`;
const rule: api.RuleDetail = {
  rule_id: "rule_test", version_id: qualityFixture.rule_version_id, semantic_hash: qualityFixture.rule_semantic_hash,
  lifecycle: "experimental", validations: [], scenarios: [], publication: null, ai_verification: null,
  quality_report: qualityFixture,
  verifier_record: { packet_id: "packet_test", pipeline_run_id: "pipeline_test", recorded_at: "2026-10-03T00:00:00Z",
    rule_version_id: qualityFixture.rule_version_id, rule_semantic_hash: qualityFixture.rule_semantic_hash,
    evidence_snapshot_hash: qualityFixture.evidence_snapshot_hash, request_hash: digest, response_hash: digest,
    provider: "fake", model: "schema-only", prompt_version: "verifier-prompt-0.1", ontology_version: "foundry-ontology-0.1",
    verdict: "pass", findings: ["Harness only"], citations: [], evidence: [] },
};
beforeEach(() => {
  vi.mocked(api.getReviewState).mockResolvedValue({ requestId: null, data: { rule_version_id: rule.version_id!, scope: "read_only_account_analysis", latest: null } });
});
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it("blocks missing or mismatched assurance without reading review state", () => {
  render(<ReviewPanel rule={{ ...rule, verifier_record: null }} />);
  expect(screen.getByText("Exact-input review unavailable")).toBeTruthy();
  expect(api.getReviewState).not.toHaveBeenCalled();
  expect(reviewBinding({ ...rule, semantic_hash: digest })).toBeNull();
});

it("keeps disabled operator mode read-only", async () => {
  vi.mocked(api.getReviewState).mockRejectedValue(new api.FoundryApiError(503, "local_review_disabled", null));
  render(<ReviewPanel rule={rule} />);
  await screen.findByText(/Local review disabled/);
  expect(screen.queryByRole("button", { name: "Record scoped decision" })).toBeNull();
});

it("confirms exact inputs and retries an uncertain result with the same request id", async () => {
  vi.mocked(api.recordReview).mockRejectedValueOnce(new Error("network"));
  vi.mocked(api.recordReview).mockImplementationOnce(async (command) => ({ requestId: null, data: {
    decision_id: "review_test", command, reviewer_alias: "configured_operator", decided_at: "2026-10-03T00:00:00Z", record_hash: digest,
  } }));
  render(<ReviewPanel rule={rule} />);
  await screen.findByText("No decision recorded for this scope.");
  fireEvent.change(screen.getByLabelText("Non-sensitive review comment"), { target: { value: "Need more context" } });
  fireEvent.click(screen.getByLabelText("I reviewed this exact version and selected scope."));
  fireEvent.click(screen.getByRole("button", { name: "Record scoped decision" }));
  await screen.findByText(/Recording outcome unavailable/);
  fireEvent.click(screen.getByRole("button", { name: "Retry unchanged decision" }));
  await screen.findByText(/Decision recorded. No stable publication/);
  expect(api.recordReview).toHaveBeenCalledTimes(2);
  expect(vi.mocked(api.recordReview).mock.calls[0][0]).toEqual(vi.mocked(api.recordReview).mock.calls[1][0]);
  expect(vi.mocked(api.recordReview).mock.calls[0][0]).not.toHaveProperty("reviewer_alias");
});

it("blocks new submissions after a stale conflict", async () => {
  vi.mocked(api.recordReview).mockRejectedValue(new api.FoundryApiError(409, "review_conflict", null));
  render(<ReviewPanel rule={rule} />);
  await screen.findByText("No decision recorded for this scope.");
  fireEvent.change(screen.getByLabelText("Non-sensitive review comment"), { target: { value: "Need evidence" } });
  fireEvent.click(screen.getByLabelText("I reviewed this exact version and selected scope."));
  fireEvent.click(screen.getByRole("button", { name: "Record scoped decision" }));
  await screen.findByText(/Review conflict/);
  await waitFor(() => expect(screen.queryByRole("button", { name: "Record scoped decision" })).toBeNull());
});

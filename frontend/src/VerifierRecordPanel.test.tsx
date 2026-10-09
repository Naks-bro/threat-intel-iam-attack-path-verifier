import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { VerifierRecordSummary } from "./generated/verifier-types";
import { VerifierRecordPanel } from "./VerifierRecordPanel";

export const record: VerifierRecordSummary = {
  packet_id: "vpacket_test", pipeline_run_id: "pipeline_test", recorded_at: "2026-10-03T00:00:00Z",
  rule_version_id: "version_test", rule_semantic_hash: `sha256:${"1".repeat(64)}`,
  evidence_snapshot_hash: `sha256:${"2".repeat(64)}`, request_hash: `sha256:${"3".repeat(64)}`,
  response_hash: `sha256:${"4".repeat(64)}`, provider: "fake", model: "schema-only",
  prompt_version: "verifier-prompt-0.1", ontology_version: "foundry-ontology-0.1", verdict: "pass",
  findings: ["Deterministic checks passed"], citations: ["evidence_test"],
  evidence: [{ evidence_id: "evidence_test", source_key: "mitre-attack", source_version: "19.2",
    content_hash: `sha256:${"5".repeat(64)}` }],
};

afterEach(cleanup);

describe("VerifierRecordPanel", () => {
  it("keeps missing exact history distinct from legacy verifier results", () => {
    render(<VerifierRecordPanel record={null} versionId="version_test" semanticHash={record.rule_semantic_hash} />);
    expect(screen.getByRole("status").textContent).toContain("Exact verifier record unavailable");
  });
  it("shows full binding metadata without calling a fake independent AI", () => {
    render(<VerifierRecordPanel record={record} versionId="version_test" semanticHash={record.rule_semantic_hash} />);
    expect(screen.getByText(record.request_hash)).toBeTruthy();
    expect(screen.getByText(record.response_hash)).toBeTruthy();
    expect(screen.getByText(/Schema-only fake; no independent AI verification/)).toBeTruthy();
    expect(screen.getByText("Deterministic checks passed")).toBeTruthy();
  });
  it("refuses a record for another version", () => {
    render(<VerifierRecordPanel record={record} versionId="other_version" semanticHash={record.rule_semantic_hash} />);
    expect(screen.getByRole("alert").textContent).toContain("Verifier record binding mismatch");
    expect(screen.queryByText(record.request_hash)).toBeNull();
  });
  it("renders untrusted finding text without interpreting HTML", () => {
    render(<VerifierRecordPanel record={{...record, findings: ["<script>bad()</script>"]}} versionId="version_test" semanticHash={record.rule_semantic_hash} />);
    expect(screen.getByText("<script>bad()</script>")).toBeTruthy();
    expect(document.querySelector("script")).toBeNull();
  });
});

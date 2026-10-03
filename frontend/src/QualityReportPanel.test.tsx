import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { QualityReportPanel } from "./QualityReportPanel";
import { qualityFixture as report } from "./generated/quality-fixture";

afterEach(cleanup);

describe("QualityReportPanel", () => {
  it("does not infer a report from summary counts when an old rule has none", () => {
    render(<QualityReportPanel report={null} versionId="version_test" semanticHash="sha256:rule" />);
    expect(screen.getByText("Versioned quality report unavailable")).toBeTruthy();
    expect(screen.queryByText("pass")).toBeNull();
  });

  it("shows exact binding, missing timing, skipped checks, and findings", () => {
    render(<QualityReportPanel report={report} versionId={report.rule_version_id} semanticHash={report.rule_semantic_hash} />);
    expect(screen.getByText(report.evidence_snapshot_hash)).toBeTruthy();
    expect(screen.getByText(report.report_hash)).toBeTruthy();
    expect(screen.getByText("incomplete")).toBeTruthy();
    expect(screen.getByText("skipped")).toBeTruthy();
    expect(screen.getAllByText("Not measured")).toHaveLength(14);
    expect(screen.getByText("No result was recorded for this required check.")).toBeTruthy();
  });

  it("refuses to display a report bound to another rule version", () => {
    render(<QualityReportPanel report={report} versionId="version_changed" semanticHash={report.rule_semantic_hash} />);
    expect(screen.getByRole("alert").textContent).toContain("Quality report binding mismatch");
    expect(screen.queryByText(report.report_hash)).toBeNull();
  });
});

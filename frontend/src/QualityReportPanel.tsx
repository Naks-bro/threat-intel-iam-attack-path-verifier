import type { QualityReport } from "./generated/quality-types";
import { StatusTag } from "./FoundryStatus";

export function QualityReportPanel({ report, versionId, semanticHash }: {
  report: QualityReport | null | undefined; versionId: string | undefined; semanticHash: string;
}) {
  if (!report) return <div className="quality-report-missing" role="status"><strong>Versioned quality report unavailable</strong><p>Individual check results may exist, but no bound report is exposed for this version. Missing reports are not a passing quality gate.</p></div>;
  if (report.rule_version_id !== versionId || report.rule_semantic_hash !== semanticHash) {
    return <div className="quality-report-missing" role="alert"><strong>Quality report binding mismatch</strong><p>The report does not match the selected immutable candidate. Do not use it for review or publication.</p></div>;
  }
  return <section className="quality-report" aria-labelledby="quality-report-title">
    <div className="quality-report-heading"><h4 id="quality-report-title">Versioned quality report</h4><StatusTag value={report.status} /></div>
    <p>Deterministic checks only. A passing report is not AI review, human approval, or proof of exploitability.</p>
    <dl className="quality-bindings">
      <div><dt>Rule version</dt><dd><code>{report.rule_version_id}</code></dd></div>
      <div><dt>Evidence snapshot</dt><dd><code>{report.evidence_snapshot_hash}</code></dd></div>
      <div><dt>Report identity</dt><dd><code>{report.report_hash}</code></dd></div>
      <div><dt>Required checks</dt><dd>{report.required_passed}/{report.required_total} passed · {report.optional_unavailable} optional tools unavailable</dd></div>
    </dl>
    <details className="quality-stage-details">
      <summary>Report stage metadata · {report.stages.length} checks</summary>
      <ul>{report.stages.map((stage) => <li key={stage.stage_id}>
        <div className="quality-stage-heading"><strong>{stage.stage_id.replaceAll("_", " ")}</strong><StatusTag value={stage.status} /></div>
        <dl><div><dt>Scope</dt><dd>{stage.required ? "Required" : "Optional"}</dd></div><div><dt>Validator version</dt><dd><code>{stage.validator_version}</code></dd></div><div><dt>Corpus version</dt><dd><code>{stage.corpus_version ?? "Not recorded"}</code></dd></div><div><dt>Duration</dt><dd>{stage.duration_ms == null ? "Not measured" : `${stage.duration_ms} ms`}</dd></div></dl>
        {stage.findings?.map((finding, index) => <p key={`${finding.code}-${index}`}>{finding.message}</p>)}
      </li>)}</ul>
    </details>
  </section>;
}

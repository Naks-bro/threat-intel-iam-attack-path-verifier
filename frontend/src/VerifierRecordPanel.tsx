import type { VerifierRecordSummary } from "./generated/verifier-types";
import { StatusTag } from "./FoundryStatus";

export function verifierRecordMatches(record: VerifierRecordSummary, versionId: string | undefined, semanticHash: string, evidenceHash?: string) {
  return record.rule_version_id === versionId && record.rule_semantic_hash === semanticHash
    && (!evidenceHash || record.evidence_snapshot_hash === evidenceHash);
}

export function VerifierRecordPanel({ record, versionId, semanticHash, evidenceHash }: {
  record: VerifierRecordSummary | null | undefined; versionId: string | undefined;
  semanticHash: string; evidenceHash?: string;
}) {
  if (!record) return <div className="quality-report-missing" role="status"><strong>Exact verifier record unavailable</strong><p>A legacy verifier summary may exist, but its exact inputs are not retained here. Missing history is not a verified input binding.</p></div>;
  if (!verifierRecordMatches(record, versionId, semanticHash, evidenceHash)) {
    return <div className="quality-report-missing" role="alert"><strong>Verifier record binding mismatch</strong><p>This record does not match the selected candidate. Do not use it for review or publication.</p></div>;
  }
  return <section className="quality-report" aria-labelledby="verifier-record-title">
    <div className="quality-report-heading"><h4 id="verifier-record-title">Recorded verifier input binding</h4><StatusTag value={record.verdict} /></div>
    <p>{record.provider === "fake" ? "Schema-only fake; no independent AI verification." : "Recorded verifier result; its presence does not establish independent correctness."} Input binding was rechecked by the API. This is not human approval, stable publication, or proof of exploitability.</p>
    <dl className="quality-bindings">
      <div><dt>Rule version</dt><dd><code>{record.rule_version_id}</code></dd></div>
      <div><dt>Evidence snapshot</dt><dd><code>{record.evidence_snapshot_hash}</code></dd></div>
      <div><dt>Record identity</dt><dd><code>{record.packet_id}</code></dd></div>
      <div><dt>Request digest</dt><dd><code>{record.request_hash}</code></dd></div>
      <div><dt>Response digest</dt><dd><code>{record.response_hash}</code></dd></div>
      <div><dt>Pipeline run</dt><dd><code>{record.pipeline_run_id}</code></dd></div>
      <div><dt>Recorded at</dt><dd><time dateTime={record.recorded_at}>{record.recorded_at}</time></dd></div>
      <div><dt>Verifier / prompt / ontology</dt><dd>{record.provider} / {record.model} · {record.prompt_version} · {record.ontology_version}</dd></div>
    </dl>
    <details className="quality-stage-details">
      <summary>Verifier findings and evidence metadata · {record.evidence.length} inputs</summary>
      {record.findings.map((finding, index) => <p key={index}>{finding}</p>)}
      <ul>{record.evidence.map((item) => <li key={item.evidence_id}>
        <strong>{item.source_key} · {item.source_version}</strong>
        <dl><div><dt>Evidence identity</dt><dd><code>{item.evidence_id}</code></dd></div><div><dt>Content digest</dt><dd><code>{item.content_hash}</code></dd></div><div><dt>Cited in response</dt><dd>{record.citations.includes(item.evidence_id) ? "Yes" : "No"}</dd></div></dl>
      </li>)}</ul>
      <p>Raw source text is not included in this dossier response.</p>
    </details>
  </section>;
}

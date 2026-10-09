import { useEffect, useRef, useState } from "react";
import { FoundryApiError, getReviewState, recordReview, type RuleDetail } from "./foundry-api";
import type { ReviewCommand, ReviewRecord } from "./generated/review-types";

type Binding = Pick<ReviewCommand, "rule_version_id" | "rule_semantic_hash" | "evidence_snapshot_hash" | "quality_report_hash" | "verifier_request_hash" | "verifier_response_hash">;

export function reviewBinding(rule: RuleDetail): Binding | null {
  const quality = rule.quality_report, verifier = rule.verifier_record;
  if (!quality || !verifier || !rule.version_id || quality.rule_version_id !== rule.version_id
    || verifier.rule_version_id !== rule.version_id || quality.rule_semantic_hash !== rule.semantic_hash
    || verifier.rule_semantic_hash !== rule.semantic_hash || quality.evidence_snapshot_hash !== verifier.evidence_snapshot_hash) return null;
  const binding = { rule_version_id: rule.version_id, rule_semantic_hash: rule.semantic_hash,
    evidence_snapshot_hash: quality.evidence_snapshot_hash, quality_report_hash: quality.report_hash,
    verifier_request_hash: verifier.request_hash, verifier_response_hash: verifier.response_hash };
  return Object.entries(binding).every(([key, value]) => key === "rule_version_id" || /^sha256:[0-9a-f]{64}$/.test(value)) ? binding : null;
}

function matches(record: ReviewRecord, binding: Binding, scope: ReviewCommand["scope"]): boolean {
  return record.command.scope === scope && Object.entries(binding).every(([key, value]) => record.command[key as keyof Binding] === value);
}

export function ReviewPanel({ rule }: { rule: RuleDetail }) {
  const binding = reviewBinding(rule);
  if (!binding) return <section className="quality-report-missing" role="status"><strong>Exact-input review unavailable</strong><p>Matching stored quality and verifier inputs are required. Preview and legacy summaries cannot supply them.</p></section>;
  return <BoundReview key={JSON.stringify(binding)} binding={binding} />;
}

function BoundReview({ binding }: { binding: Binding }) {
  const [scope, setScope] = useState<ReviewCommand["scope"]>("read_only_account_analysis");
  const [decision, setDecision] = useState<ReviewCommand["decision"]>("revision_requested");
  const [comment, setComment] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [available, setAvailable] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("Loading scoped review…");
  const [latest, setLatest] = useState<ReviewRecord | null>(null);
  const [retry, setRetry] = useState(false);
  const pending = useRef<ReviewCommand | null>(null);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => {
    const abort = new AbortController();
    setAvailable(false); setLatest(null); setConfirmed(false); setMessage("Loading scoped review…");
    getReviewState(binding.rule_version_id, scope, abort.signal).then(({ data }) => {
      if (abort.signal.aborted) return;
      if (data.rule_version_id !== binding.rule_version_id || data.scope !== scope) throw new Error("binding");
      setLatest(data.latest); setAvailable(true);
      setMessage(data.latest ? "Latest scoped history loaded. Release eligibility is not evaluated." : "No decision recorded for this scope.");
    }).catch((error: unknown) => {
      if (abort.signal.aborted) return;
      setMessage(error instanceof FoundryApiError && error.code === "local_review_disabled"
        ? "Local review disabled. Enable operator mode on the API; the browser cannot choose an identity."
        : "Scoped review unavailable. No decision is inferred; check the API and reload the dossier.");
    });
    return () => abort.abort();
  }, [binding.rule_version_id, scope]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!available || busy || !confirmed) return;
    const command = pending.current ?? { ...binding, request_id: `review_${crypto.randomUUID()}`, scope, decision, comment: comment.trim() };
    pending.current = command; setBusy(true); setMessage("Recording exact-input decision…");
    try {
      const { data } = await recordReview(command);
      if (!alive.current) return;
      if (!matches(data, binding, scope) || data.command.request_id !== command.request_id
        || data.command.decision !== command.decision || (data.command.comment ?? "") !== (command.comment ?? "")) throw new Error("binding");
      setLatest(data); pending.current = null; setRetry(false); setConfirmed(false);
      setMessage("Decision recorded. No stable publication or AWS action was performed.");
    } catch (error: unknown) {
      if (!alive.current) return;
      if (error instanceof FoundryApiError && error.code === "review_conflict") {
        setAvailable(false); setRetry(false);
        setMessage("Review conflict. Reload the dossier and inspect current inputs before making a new decision.");
      } else if (error instanceof FoundryApiError && error.status === 422) {
        pending.current = null; setRetry(false); setMessage("Decision rejected by validation. Check the non-sensitive comment and decision.");
      } else {
        setRetry(true); setMessage("Recording outcome unavailable. Retry the unchanged request to avoid a duplicate decision; do not assume it was saved.");
      }
    } finally { if (alive.current) setBusy(false); }
  }

  return <section className="quality-report review-panel" aria-labelledby="review-title">
    <h4 id="review-title">Exact-input operator review</h4>
    <p>Local operator alias, not authenticated identity. Decisions do not approve AWS writes, publish stable rules, or prove exploitability.</p>
    <label>Approval scope<select value={scope} disabled={busy || retry} onChange={(event) => setScope(event.target.value as ReviewCommand["scope"])}>
      <option value="read_only_account_analysis">Read-only account analysis</option><option value="isolated_lab_validation">Isolated lab validation</option><option value="synthetic_benchmark">Synthetic benchmark</option>
    </select></label>
    <p role="status" aria-live="polite">{message}</p>
    {latest ? <dl className="quality-bindings"><div><dt>Latest decision / operator</dt><dd>{latest.command.decision} / {latest.reviewer_alias}</dd></div><div><dt>Current dossier binding</dt><dd>{matches(latest, binding, scope) ? "Matches displayed inputs; release eligibility not evaluated" : "Historical inputs differ; not current approval"}</dd></div><div><dt>Decision identity</dt><dd><code>{latest.decision_id}</code></dd></div><div><dt>Comment</dt><dd>{latest.command.comment || "No comment"}</dd></div></dl> : null}
    {available ? <form onSubmit={submit}>
      <fieldset disabled={busy || retry}><legend>Review the displayed immutable inputs</legend>
        <label>Decision<select value={decision} onChange={(event) => setDecision(event.target.value as ReviewCommand["decision"])}><option value="revision_requested">Request revision</option><option value="rejected">Reject</option><option value="approved">Approve for selected scope</option></select></label>
        <label>Non-sensitive review comment<textarea maxLength={2000} required={decision !== "approved"} value={comment} onChange={(event) => setComment(event.target.value)} /></label>
        <label className="review-confirm"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />I reviewed this exact version and selected scope.</label>
      </fieldset>
      <button type="submit" disabled={busy || !confirmed || (decision !== "approved" && !comment.trim())}>{busy ? "Recording…" : retry ? "Retry unchanged decision" : "Record scoped decision"}</button>
    </form> : null}
  </section>;
}

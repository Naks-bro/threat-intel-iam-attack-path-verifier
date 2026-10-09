import { useEffect, useState } from "react";
import { FoundryApiError, analyzeCredentialFixture, getRealAccountObservation, type CredentialAnalysis, type RealAccountObservation } from "./foundry-api";
import { TimelineCanvas, type TimelineStation } from "./TimelineCanvas";
import { WhatIfPanel } from "./WhatIfPanel";

const identities = [
  { key: "exposed", id: "principal:user/developer", label: "Developer", role: "Exposed comparator" },
  { key: "control", id: "principal:user/control", label: "Control user", role: "Control comparator" },
] as const;
type IdentityKey = typeof identities[number]["key"];
type Reports = Record<IdentityKey, CredentialAnalysis>;
type ViewState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; reports: Reports };

export type SealedOutcome = "candidate_from_policy_text" | "no_matching_statement" | "unknown";

export type SealedIdentity = {
  key: string;
  label: string;
  outcome: SealedOutcome;
};

export type SealedPair = {
  dataKind: "real_account_observed";
  snapshotDigest: string;
  ruleVersion: number;
  ruleDigest: string;
  identities: readonly [SealedIdentity, SealedIdentity];
};

const LOCAL_REVIEW_LIMIT =
  "Local operator review is not authenticated authority and not exploit proof.";

function sealedLabel(outcome: SealedOutcome): string {
  if (outcome === "candidate_from_policy_text") return "Candidate from policy text";
  if (outcome === "no_matching_statement") return "No matching statement";
  return "Unknown";
}

function sealedExplanation(outcome: SealedOutcome): string {
  if (outcome === "candidate_from_policy_text") {
    return "An Allow statement is policy text. It is not an AWS authorization decision or exploit proof.";
  }
  if (outcome === "no_matching_statement") {
    return "No identity-policy statement matched the additional-credentials rule. This is a scoped observation, not a certificate.";
  }
  return "The result is unknown. A missing group traversal or another gap cannot be read as a clean result.";
}

type CaseAssessment = {
  kind: "unknown" | "inconsistent" | "candidate" | "denied" | "needs_context" | "no_path";
  label: string;
  explanation: string;
};

function assessFixture(report: CredentialAnalysis): CaseAssessment {
  const count = report.attack_paths.length;
  if (count !== report.findings.length || count !== report.verifications.length) {
    return { kind: "inconsistent", label: "Result incomplete", explanation: "The fixture API returned unmatched paths, findings or verification records. Do not interpret this result until the API is checked." };
  }
  if (report.input_rule_refs.length === 0) {
    return { kind: "unknown", label: "No rule tested", explanation: "No rule was evaluated for this identity, so there is no negative or positive result." };
  }
  // Only this known structural-negative issue may coexist with a scoped no-path claim.
  // New issue codes fail closed until the portal deliberately handles them.
  if (report.issues.some((issue) => issue.code !== "precondition_not_met")) {
    return { kind: "unknown", label: "Unknown / partial", explanation: "The analysis reported a collection, rule or search limitation. Inspect the issues below before interpreting any path or absence of a path." };
  }
  if (report.verifications.some((item) => item.status === "supported_by_fixture")) {
    return { kind: "candidate", label: "Candidate path", explanation: "A derived permission edge matches the credential-creation rule in this fixture. This does not establish effective AWS permission or exploitability." };
  }
  if (count > 0 && report.verifications.every((item) => item.status === "denied_by_fixture")) {
    return { kind: "denied", label: "Denied in fixture", explanation: "A structural path was found, but the fixture verifier denied every displayed path. This is not an AWS authorization result." };
  }
  if (count > 0) {
    return { kind: "needs_context", label: "Path needs context", explanation: "A structural path exists, but the fixture has not established a supported or denied outcome for every path." };
  }
  return { kind: "no_path", label: "No path for tested rule", explanation: "No candidate path was found for this identity under the tested rule, snapshot and search limits. This is a scoped negative result, not a security certificate." };
}

function stationFor(item: typeof identities[number], report: CredentialAnalysis): TimelineStation {
  const assessment = assessFixture(report);
  const path = report.attack_paths[0];
  const kind = assessment.kind;
  const nexus = path && (kind === "candidate" || kind === "denied" || kind === "needs_context")
    ? {
        kind,
        action: path.hops[0]?.required_action ?? "unspecified action",
        targetLabel: nameFromId(path.goal_node_id),
        extraPaths: Math.max(0, report.attack_paths.length - 1),
      }
    : null;
  return { key: item.key, label: item.label, detail: assessment.label, nexus };
}

function nameFromId(id: string): string {
  return id.split("/").at(-1) ?? id;
}

function sameInputs(exposed: CredentialAnalysis, control: CredentialAnalysis): boolean {
  const digest = /^sha256:[0-9a-f]{64}$/;
  return exposed.start_node_id === identities[0].id
    && control.start_node_id === identities[1].id
    && exposed.snapshot_id === control.snapshot_id
    && digest.test(exposed.graph_input_digest)
    && exposed.graph_input_digest === control.graph_input_digest
    && digest.test(exposed.input_rule_digest)
    && exposed.input_rule_digest === control.input_rule_digest;
}

function SourceSwitch({ mode, onChange }: {
  mode: "synthetic" | "sealed";
  onChange: (mode: "synthetic" | "sealed") => void;
}) {
  return <div role="group" aria-label="Observation source">
    <button type="button" aria-pressed={mode === "synthetic"} onClick={() => onChange("synthetic")}>Synthetic credential fixture</button>
    <button type="button" aria-pressed={mode === "sealed"} onClick={() => onChange("sealed")}>Real-account observation</button>
  </div>;
}

type RemoteSeal =
  | { status: "loading" }
  | { status: "absent" }
  | { status: "error"; message: string }
  | { status: "ready"; pair: SealedPair };

function pairFromObservation(data: RealAccountObservation): SealedPair | null {
  if (data.authorization_evaluated !== false || data.data_kind !== "real_account_observed" || data.identities.length !== 2) {
    return null;
  }
  const [first, second] = data.identities;
  return {
    dataKind: "real_account_observed",
    snapshotDigest: data.snapshot_digest,
    ruleVersion: data.rule_version,
    ruleDigest: data.rule_digest,
    identities: [
      { key: first.key, label: first.label, outcome: first.outcome },
      { key: second.key, label: second.label, outcome: second.outcome },
    ],
  };
}

export function InvestigationPage({ sealedPair }: { sealedPair?: SealedPair | null }) {
  const supplied = sealedPair !== undefined;
  const [view, setView] = useState<ViewState>({ status: "loading" });
  const [selected, setSelected] = useState<IdentityKey | null>(null);
  const [mode, setMode] = useState<"synthetic" | "sealed">("synthetic");
  const [sealedSelected, setSealedSelected] = useState<string | null>(null);
  const [remote, setRemote] = useState<RemoteSeal>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    Promise.all(identities.map((identity) => analyzeCredentialFixture(identity.id, controller.signal)))
      .then(([exposed, control]) => {
        if (!sameInputs(exposed.data, control.data)) {
          setView({ status: "error", message: "The fixture results did not pin the same graph and rule inputs. Check the API, then refresh." });
          return;
        }
        setView({ status: "ready", reports: { exposed: exposed.data, control: control.data } });
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setView({ status: "error", message: "The local fixture API is unavailable. Start the API and refresh." });
        }
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (supplied || mode !== "sealed") return;
    const controller = new AbortController();
    setRemote({ status: "loading" });
    getRealAccountObservation(controller.signal)
      .then((result) => {
        const pair = pairFromObservation(result.data);
        if (!pair) {
          setRemote({ status: "error", message: "The sealed observation did not contain two real-account starting identities. Authorization was not evaluated." });
          return;
        }
        setRemote({ status: "ready", pair });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        if (error instanceof FoundryApiError && error.status === 404) {
          setRemote({ status: "absent" });
          return;
        }
        if (error instanceof FoundryApiError && error.code === "starting_user_count_unsupported") {
          setRemote({ status: "error", message: "The sealed observation does not contain exactly two starting users. Authorization was not evaluated." });
          return;
        }
        setRemote({ status: "error", message: "The local sealed observation could not be loaded. The synthetic fixture is still available. Authorization was not evaluated." });
      });
    return () => controller.abort();
  }, [supplied, mode]);

  if (mode === "sealed") {
    const pair = supplied ? sealedPair ?? null : remote.status === "ready" ? remote.pair : null;
    return <div className="investigation-page">
      <SourceSwitch mode={mode} onChange={setMode} />
      {!supplied && remote.status === "loading" ? <section className="control-panel investigation-state" aria-busy="true">Loading the sealed real-account observation…</section> : null}
      {!supplied && remote.status === "error" ? <section className="control-panel investigation-state" role="alert"><h2>Real-account observation unavailable</h2><p>{remote.message}</p></section> : null}
      {supplied || remote.status === "ready" || remote.status === "absent" ? <SealedObservation pair={pair} selectedKey={sealedSelected} onSelect={setSealedSelected} /> : null}
    </div>;
  }
  if (view.status === "loading") {
    return <div className="investigation-page">
      <SourceSwitch mode={mode} onChange={setMode} />
      <section className="control-panel investigation-state" aria-busy="true">Loading the two synthetic identity analyses…</section>
    </div>;
  }
  if (view.status === "error") {
    return <div className="investigation-page">
      <SourceSwitch mode={mode} onChange={setMode} />
      <section className="control-panel investigation-state" role="alert"><h2>Investigation unavailable</h2><p>{view.message}</p></section>
    </div>;
  }

  const { reports } = view;
  const identity = identities.find((item) => item.key === selected);
  const report = selected ? reports[selected] : null;
  const assessment = report ? assessFixture(report) : null;
  const finding = report?.findings[0];
  const path = report?.attack_paths[0];
  const verification = report?.verifications[0];

  return <div className="investigation-page">
    <SourceSwitch mode={mode} onChange={setMode} />
    <div className="investigation-banner" role="status">
      <strong>TIMELINE</strong>
      <span>Synthetic credential fixture. Two starting identities on one checked-in snapshot. A nexus event is a possible branch. No AWS account was scanned, no simulator ran, and no key was created.</span>
    </div>
    <TimelineCanvas
      snapshotId={reports.exposed.snapshot_id}
      stations={identities.map((item) => stationFor(item, reports[item.key]))}
      selectedKey={selected}
      onSelect={(key) => setSelected(key as IdentityKey)}
    />
    <section className="control-panel identity-ledger" aria-labelledby="identity-ledger-title">
      <div className="identity-ledger-heading">
        <div><p className="section-code">INVESTIGATION QUEUE / LOCAL FIXTURE</p><h2 id="identity-ledger-title">Choose a starting identity</h2></div>
        <span>Same snapshot · same rule inputs</span>
      </div>
      <div className="identity-ledger-rows">
        {identities.map((item) => <button type="button" key={item.key} className="identity-ledger-row" aria-pressed={selected === item.key} onClick={() => setSelected(item.key)}>
          <span className="identity-ledger-name"><strong>{item.label}</strong><small>{item.role}</small></span>
          <code>{item.id}</code>
          <span className="identity-ledger-result">{assessFixture(reports[item.key]).label}</span>
          <span className="identity-ledger-open" aria-hidden="true">Inspect →</span>
        </button>)}
      </div>
      <p className="page-note">“No path” applies only to this rule, snapshot and search. It does not certify an identity or account as secure.</p>
    </section>
    {!report || !identity ? <section className="control-panel investigation-state" role="status"><h2>No identity selected</h2><p>Choose either row to inspect its evidence and limitations.</p></section> : <div className="investigation-detail" aria-live="polite">
      <section className="control-panel investigation-summary" aria-labelledby="finding-title">
        <div className="investigation-heading"><div><p className="section-code">IDENTITY / {identity.role.toUpperCase()}</p><h2 id="finding-title">{identity.label}</h2></div><span className="investigation-verdict">{assessment?.label}</span></div>
        <p>{assessment?.explanation}</p>
        <dl className="investigation-facts"><div><dt>Snapshot</dt><dd><code>{report.snapshot_id}</code></dd></div><div><dt>Graph-input digest</dt><dd><code>{report.graph_input_digest}</code></dd></div><div><dt>Rule</dt><dd>{report.input_rule_refs.map((item) => `${item.rule_id} v${item.rule_version}`).join(", ") || "none"}</dd></div><div><dt>Rule-input digest</dt><dd><code>{report.input_rule_digest}</code></dd></div></dl>
        {report.issues.length > 0 && <div className="investigation-issues"><h3>Analysis limitations</h3><ul>{report.issues.map((issue) => <li key={`${issue.code}-${issue.message}`}>{issue.message}</li>)}</ul></div>}
      </section>
      {assessment?.kind !== "inconsistent" && finding && path && verification ? <>
        <section className="control-panel investigation-path" aria-labelledby="path-title">
          <p className="section-code">PERMISSION PATH / ONE DERIVED STEP</p><h2 id="path-title">How the path works</h2>
          {report.attack_paths.length > 1 && <p className="page-note">Showing the first of {report.attack_paths.length} fixture paths. The label above summarizes all returned paths.</p>}
          <div className="investigation-flow"><div className="investigation-identity"><span>Starting identity</span><strong>{nameFromId(path.start_node_id)}</strong><code>{path.start_node_id}</code></div><div className="investigation-action"><span aria-hidden="true">→</span><code>{path.hops[0]?.required_action ?? "unknown action"}</code></div><div className="investigation-identity"><span>Target identity</span><strong>{nameFromId(path.goal_node_id)}</strong><code>{path.goal_node_id}</code></div></div>
          <p className="page-note">The edge is a synthetic, policy-referenced assertion. Fixture support does not prove AWS would allow the API call.</p>
        </section>
        {selected === "exposed" && path.hops[0] && <WhatIfPanel edgeId={path.hops[0].edge_id} action={path.hops[0].required_action} />}
        <div className="investigation-columns">
          <section className="control-panel" aria-labelledby="evidence-title"><p className="section-code">TRACEABILITY</p><h2 id="evidence-title">Evidence carried into the finding</h2><ul className="investigation-list">{finding.explanation.evidence.map((reference) => <li key={reference}><code>{reference}</code></li>)}</ul><p className="page-note">Fixture and source references only; no raw AWS policy document.</p></section>
          <section className="control-panel" aria-labelledby="limits-title"><p className="section-code">VERIFICATION BOUNDARY</p><h2 id="limits-title">What remains unknown</h2><ul className="investigation-list">{verification.limitations.map((limit) => <li key={limit}>{limit}</li>)}</ul>{verification.local_fixture.missing_context.length > 0 && <p>Missing context: {verification.local_fixture.missing_context.join(", ")}</p>}</section>
        </div>
        <section className="control-panel investigation-next" aria-labelledby="next-title"><p className="section-code">HUMAN DECISION</p><h2 id="next-title">Review before raising an IT ticket</h2><p>{finding.remediation[0]?.proposal ?? "Review the cited permission with the account owner."}</p><span>No change is applied automatically.</span><a className="workspace-link" href="#/rules">Inspect the rule workshop <span aria-hidden="true">↗</span></a></section>
      </> : <section className="control-panel investigation-state"><h2>What this result does not say</h2><p>{assessment?.kind === "no_path" ? "This rule found no candidate path in the synthetic snapshot. Other rules, identities, policy layers and AWS runtime context were not tested here." : "This result does not support a clean or vulnerable label. Review the analysis limitations and exact inputs before making a decision."}</p></section>}
    </div>}
  </div>;
}

function SealedObservation({ pair, selectedKey, onSelect }: {
  pair: SealedPair | null;
  selectedKey: string | null;
  onSelect: (key: string) => void;
}) {
  if (!pair) {
    return <section className="control-panel investigation-state" role="status">
      <h2>Real-account observation</h2>
      <p>No sealed snapshot is loaded in this session.</p>
    </section>;
  }
  const selected = pair.identities.find((identity) => identity.key === selectedKey) ?? null;
  return <div>
    <div className="investigation-banner" role="status">
      <strong>TIMELINE</strong>
      <span>Real-account observation. Two starting identities share one snapshot digest and one rule digest. A nexus event is policy text only. Authorization was not evaluated. {LOCAL_REVIEW_LIMIT}</span>
    </div>
    <TimelineCanvas
      snapshotId={pair.snapshotDigest}
      stations={pair.identities.map((identity) => ({
        key: identity.key,
        label: identity.label,
        detail: sealedLabel(identity.outcome),
        nexus: identity.outcome === "candidate_from_policy_text"
          ? { kind: "policy_text", action: "iam:CreateAccessKey", targetLabel: "Policy text only", extraPaths: 0 }
          : null,
      }))}
      selectedKey={selectedKey}
      onSelect={onSelect}
    />
    <section className="control-panel identity-ledger" aria-labelledby="sealed-ledger-title">
      <div className="identity-ledger-heading">
        <div><p className="section-code">INVESTIGATION QUEUE / REAL-ACCOUNT OBSERVATION</p><h2 id="sealed-ledger-title">Choose a starting identity</h2></div>
        <span>Same snapshot digest · same rule digest</span>
      </div>
      <dl className="investigation-facts">
        <div><dt>Snapshot digest</dt><dd><code>{pair.snapshotDigest}</code></dd></div>
        <div><dt>Rule</dt><dd>rule_additional_cloud_credentials v{pair.ruleVersion}</dd></div>
        <div><dt>Rule digest</dt><dd><code>{pair.ruleDigest}</code></dd></div>
      </dl>
      <div className="identity-ledger-rows">
        {pair.identities.map((identity) => <button type="button" key={identity.key} className="identity-ledger-row" aria-pressed={selectedKey === identity.key} onClick={() => onSelect(identity.key)}>
          <span className="identity-ledger-name"><strong>{identity.label}</strong><small>Starting identity</small></span>
          <code>{identity.key}</code>
          <span className="identity-ledger-result">{sealedLabel(identity.outcome)}</span>
          <span className="identity-ledger-open" aria-hidden="true">Inspect →</span>
        </button>)}
      </div>
    </section>
    {!selected ? <section className="control-panel investigation-state" role="status"><h2>No identity selected</h2><p>Choose either row to inspect its policy-text observation.</p></section> : <section className="control-panel investigation-summary" aria-live="polite" aria-labelledby="sealed-finding-title">
      <div className="investigation-heading"><div><p className="section-code">REAL-ACCOUNT OBSERVATION</p><h2 id="sealed-finding-title">{selected.label}</h2></div><span className="investigation-verdict">{sealedLabel(selected.outcome)}</span></div>
      <p>{sealedExplanation(selected.outcome)}</p>
      <p>{LOCAL_REVIEW_LIMIT}</p>
    </section>}
  </div>;
}

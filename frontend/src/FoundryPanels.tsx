import type { FoundryOverview, FoundrySource, RuleDetail } from "./foundry-api";
import { QualityReportPanel } from "./QualityReportPanel";
import { StatusTag } from "./FoundryStatus";

export { StatusTag } from "./FoundryStatus";

type IconName = "alert" | "evidence" | "overview" | "primitives" | "run" | "sources" | "verified";

export function FoundryIcon({ name }: { name: IconName }) {
  const paths: Record<IconName, React.ReactNode> = {
    alert: <path d="M12 3 2.8 19h18.4L12 3Zm0 5v5m0 3v.01" />,
    evidence: <path d="M5 5h4v4H5V5Zm10 0h4v4h-4V5ZM10 7h4M7 10v4m10-4v4M5 15h4v4H5v-4Zm10 0h4v4h-4v-4Zm-6 2h6" />,
    overview: <path d="M4 4h6v6H4V4Zm10 0h6v6h-6V4ZM4 14h6v6H4v-6Zm10 0h6v6h-6v-6Z" />,
    primitives: <path d="M12 3v4m0 10v4M3 12h4m10 0h4M6.3 6.3l2.8 2.8m5.8 5.8 2.8 2.8m0-11.4-2.8 2.8m-5.8 5.8-2.8 2.8M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z" />,
    run: <path d="m9 7 8 5-8 5V7Z" />,
    sources: <path d="M4 6c0-1.1 3.6-2 8-2s8 .9 8 2-3.6 2-8 2-8-.9-8-2Zm0 0v6c0 1.1 3.6 2 8 2s8-.9 8-2V6M4 12v6c0 1.1 3.6 2 8 2s8-.9 8-2v-6" />,
    verified: <path d="m5 12 4 4L19 6" />,
  };
  return <svg className="foundry-icon" viewBox="0 0 24 24" aria-hidden="true">{paths[name]}</svg>;
}

function humanize(value: string) { return value.replaceAll("_", " "); }

function compactHash(value: string) {
  return value.length > 25 ? `${value.slice(0, 14)}…${value.slice(-7)}` : value;
}

function sourceName(key: string) {
  const names: Record<string, string> = {
    "aws-service-reference": "AWS Service Authorization Reference",
    "aws-threat-technique-catalog": "AWS Threat Technique Catalog",
    "mitre-attack": "MITRE ATT&CK Enterprise",
    "stratus-red-team": "Stratus Red Team",
  };
  return names[key] ?? humanize(key);
}

export function PipelinePanel({ overview, rule }: { overview: FoundryOverview; rule: RuleDetail | null }) {
  const failed = overview.sources.some((source) => source.enabled && source.last_status === "failed");
  const requiredValidations = rule?.validations.filter((item) => !item.optional) ?? [];
  const passedValidations = requiredValidations.filter((item) => item.result === "pass").length;
  const stages = [
    { name: "Acquire", detail: overview.storage === "preview" ? `${overview.sources.filter((source) => source.enabled).length} pinned local sources` : `${overview.sources.filter((source) => source.enabled).length} active source attempts`, state: failed ? "warning" : overview.run && overview.sources.filter((source) => source.enabled).every((source) => source.last_status === "succeeded") ? "complete" : "waiting" },
    { name: "Normalize", detail: `${overview.primitives.length} behavior primitives`, state: overview.primitives.length ? "complete" : "waiting" },
    { name: "Correlate", detail: `${overview.relations.length} typed relations`, state: overview.relations.length ? "complete" : "waiting" },
    { name: "Compile", detail: `${overview.candidates.length} immutable version`, state: overview.candidates.length ? "complete" : "waiting" },
    { name: "Assure", detail: `${passedValidations}/${requiredValidations.length} required checks passed`, state: requiredValidations.length ? passedValidations === requiredValidations.length ? "complete" : "warning" : "waiting" },
    { name: "Release", detail: overview.storage === "preview" ? "preview only · nothing published" : rule?.publication?.channel ?? "human gate closed", state: rule?.publication ? "warning" : "waiting" },
  ];
  return (
    <section className="control-panel pipeline-control" aria-labelledby="pipeline-title">
      <PanelHeading code={overview.storage === "preview" ? "DETERMINISTIC / PREVIEW RESULT" : "AUTOMATION / LAST RUN"} title="Evidence pipeline" aside={<StatusTag value={overview.run?.status ?? "not_run"} />} id="pipeline-title" />
      <ol className="evidence-spine">
        {stages.map((stage, index) => (
          <li className={`is-${stage.state}`} key={stage.name}>
            <span className="spine-node">{String(index + 1).padStart(2, "0")}</span>
            <div><strong>{stage.name}</strong><small>{stage.detail}</small></div>
            <StatusTag value={stage.state === "complete" ? "pass" : stage.state === "warning" ? "needs_review" : "not_run"} />
          </li>
        ))}
      </ol>
      <div className="run-metadata">
        <div><span>{overview.storage === "preview" ? "Read" : "Fetched"}</span><strong>{overview.run?.fetched_count ?? 0}</strong></div>
        <div><span>{overview.storage === "preview" ? "Loaded" : "Created"}</span><strong>{overview.run?.created_count ?? 0}</strong></div>
        <div><span>Unchanged</span><strong>{overview.run?.unchanged_count ?? 0}</strong></div>
        <div><span>Rejected</span><strong>{overview.run?.rejected_count ?? 0}</strong></div>
        <code>{overview.run?.parser_version ?? "No parser run recorded"}</code>
      </div>
    </section>
  );
}

export function RulePanel({ overview, rule, onOpen }: { overview: FoundryOverview; rule: RuleDetail | null; onOpen: (versionId: string) => void }) {
  const requiredValidations = rule?.validations.filter((item) => !item.optional) ?? [];
  const validationPasses = requiredValidations.filter((item) => item.result === "pass").length;
  const optionalUnavailable = rule?.validations.filter((item) => item.optional && item.result === "unavailable").length ?? 0;
  const scenarioPasses = rule?.scenarios.filter((item) => item.result === "pass").length ?? 0;
  const fakeVerifier = rule?.ai_verification?.provider === "fake";
  return (
    <section className="control-panel release-control" aria-labelledby="release-title">
      <PanelHeading code="RULE REGISTRY / RELEASE GATE" title="Candidate assurance" aside={<StatusTag value={rule?.publication?.channel ?? "gated"} />} id="release-title" />
      {overview.candidates.length ? (
        <div className="version-selector" aria-label="Rule versions">
          {overview.candidates.map((candidate) => (
            <button type="button" key={candidate.version_id} onClick={() => onOpen(candidate.version_id)} aria-pressed={rule?.version_id === candidate.version_id}>
              <span>{candidate.rule_id}</span><small>{compactHash(candidate.semantic_hash)}</small>
            </button>
          ))}
        </div>
      ) : <EmptyPanel title="No candidate version" body="Run the evidence pipeline after source integrity is restored." />}
      {rule ? (
        <div className="rule-dossier">
          <div className="rule-heading">
            <div><span className="rule-id">{rule.rule_id}</span><h3>{rule.rule?.title ?? "Experimental rule candidate"}</h3></div>
            <StatusTag value={rule.lifecycle} />
          </div>
          <p>{rule.rule?.description ?? "Compiled from the frozen evidence snapshot."}</p>
          <dl className="rule-facts">
            <div><dt>ATT&amp;CK</dt><dd>{rule.rule?.technique_refs?.[0]?.external_id ?? "unmapped"}</dd></div>
            <div><dt>Severity</dt><dd>{rule.rule?.severity ?? "not assigned"}</dd></div>
            <div><dt>Semantic identity</dt><dd title={rule.semantic_hash}>{compactHash(rule.semantic_hash)}</dd></div>
          </dl>
          <div className="assurance-matrix">
            <article><span>Required checks</span><strong>{validationPasses}/{requiredValidations.length}</strong><small>{optionalUnavailable} optional {optionalUnavailable === 1 ? "tool" : "tools"} unavailable</small></article>
            <article>
              <span>{fakeVerifier ? "Verifier harness" : "AI critic"}</span><strong>{rule.ai_verification?.verdict ?? "absent"}</strong>
              <small>{fakeVerifier ? "Schema-only harness; no external model called" : rule.ai_verification ? `${rule.ai_verification.provider} / ${rule.ai_verification.model}` : "No verifier result stored"}</small>
            </article>
            <article><span>Scenario corpus</span><strong>{scenarioPasses}/{rule.scenarios.length}</strong><small>expected outcomes passed</small></article>
          </div>
          <QualityReportPanel report={rule.quality_report} versionId={rule.version_id} semanticHash={rule.semantic_hash} />
          {rule.validations.length ? (
            <div className="validation-review" aria-label="Validation review">
              <h4>Validation review <span>Required checks and optional tools are separate</span></h4>
              <div className="validation-list">
                {rule.validations.map((validation) => (
                  <article key={validation.validator_name}>
                    <div><strong>{humanize(validation.validator_name)}</strong><small>{validation.optional ? "Optional tool" : "Required check"}</small></div>
                    <StatusTag value={validation.result} />
                    {validation.findings?.length ? <p>{validation.findings.join(" · ")}</p> : null}
                  </article>
                ))}
              </div>
            </div>
          ) : null}
          {rule.scenarios.length ? (
            <div className="scenario-review" aria-label="Scenario review">
              <h4>Scenario review <span>{rule.scenarios.length} labeled cases</span></h4>
              <div className="scenario-list">
                {rule.scenarios.map((scenario) => (
                  <article key={scenario.scenario_id}>
                    <div><code>{scenario.scenario_id}</code><small>{humanize(scenario.case_class ?? "legacy case")}</small></div>
                    <span>Expected <strong>{humanize(scenario.expect)}</strong></span>
                    <span>Observed <strong>{humanize(scenario.actual ?? "not recorded")}</strong></span>
                    <StatusTag value={scenario.result} />
                  </article>
                ))}
              </div>
            </div>
          ) : null}
          <div className="dossier-boundaries">
            <h4>Evidence &amp; limitations</h4>
            <div><span>Referenced evidence</span>{rule.rule?.evidence_refs?.length ? rule.rule.evidence_refs.map((ref) => <code key={ref}>{ref}</code>) : <small>No evidence references in dossier</small>}</div>
            <div><span>Known limits</span>{rule.rule?.limitations?.length ? <ul>{rule.rule.limitations.map((limit) => <li key={limit}>{limit}</li>)}</ul> : <small>No limitations recorded</small>}</div>
          </div>
          <div className="release-boundary"><FoundryIcon name="alert" /><p>{overview.storage === "preview" ? <><strong>Preview isolation</strong> This candidate is not published or exported to Engine 3.</> : <><strong>Experimental isolation</strong> Engine 3 excludes this version unless a caller explicitly opts in.</>}</p></div>
        </div>
      ) : null}
    </section>
  );
}

export function SourcesPanel({ sources, previewMode = false }: { sources: FoundrySource[]; previewMode?: boolean }) {
  return (
    <section className="control-panel source-control" id="sources" aria-labelledby="sources-title">
      <PanelHeading code="INPUT AUTHORITY" title="Source intelligence" aside={<span className="panel-count">{sources.length}</span>} id="sources-title" />
      {sources.length ? (
        <div className="data-table-wrap"><table className="data-table">
          <thead><tr><th>Source</th><th>Authority</th><th>Input class</th><th>Version</th><th>{previewMode ? "Pinned status" : "Last attempt"}</th></tr></thead>
          <tbody>{sources.map((source) => (
            <tr key={source.source_key}>
              <td><strong>{sourceName(source.source_key)}</strong><code>{source.source_key}</code></td>
              <td><span className="authority-tier">Tier {source.authority_tier}</span></td><td>{humanize(source.source_type)}</td>
              <td><code>{source.version_label}</code></td><td><StatusTag value={source.last_status ?? "unknown"} /></td>
            </tr>
          ))}</tbody>
        </table></div>
      ) : <EmptyPanel title="No source attempts" body="The registry has not recorded an evidence ingestion run." />}
    </section>
  );
}

export function PrimitivesPanel({ primitives }: { primitives: FoundryOverview["primitives"] }) {
  return (
    <section className="control-panel" id="primitives" aria-labelledby="primitives-title">
      <PanelHeading code="INTERPRETED BEHAVIOR" title="Attack primitives" aside={<span className="panel-count">{primitives.length}</span>} id="primitives-title" />
      <div className="primitive-list">
        {primitives.map((primitive) => (
          <article key={primitive.primitive_key}>
            <div><StatusTag value={primitive.attack_mapping_state} /><span>{humanize(primitive.outcome_category)}</span></div>
            <h3>{primitive.primitive_key}</h3><p>{primitive.state_transition}</p>
            <ul aria-label={`Required actions for ${primitive.primitive_key}`}>{primitive.required_actions.map((action) => <li key={action}><code>{action}</code></li>)}</ul>
          </article>
        ))}
        {!primitives.length ? <EmptyPanel title="No primitives derived" body="Normalized source evidence has not produced bounded IAM behavior." /> : null}
      </div>
    </section>
  );
}

export function EvidencePanel({ relations }: { relations: FoundryOverview["relations"] }) {
  return (
    <section className="control-panel" id="evidence" aria-labelledby="evidence-title">
      <PanelHeading code="PROVENANCE LEDGER" title="Evidence map" aside={<span className="panel-count">{relations.length}</span>} id="evidence-title" />
      <div className="relation-ledger">
        {relations.map((relation) => (
          <article key={`${relation.from_native_id}-${relation.relation_type}-${relation.to_native_id}`}>
            <div className="relation-path"><code>{relation.from_native_id}</code><span><small>{humanize(relation.relation_type)}</small><b aria-hidden="true">→</b></span><code>{relation.to_native_id}</code></div>
            <StatusTag value={relation.review_state} /><p>{relation.rationale}</p>
          </article>
        ))}
        {!relations.length ? <EmptyPanel title="No evidence relations" body="No typed relationship has been persisted for this registry." /> : null}
      </div>
    </section>
  );
}

export function RegistryUnavailable({ overview }: { overview: FoundryOverview }) {
  return (
    <section className="registry-unavailable" aria-labelledby="registry-unavailable-title">
      <div className="degraded-symbol" aria-hidden="true"><span /><span /><span /></div>
      <div><p className="section-code">CONTROL PLANE / DEGRADED</p><h2 id="registry-unavailable-title">Registry evidence is unavailable</h2><p>FastAPI is responding, but the foundry cannot establish a trusted PostgreSQL view. Candidate data is intentionally not inferred from pins or browser state.</p></div>
      <dl><div><dt>Database state</dt><dd>{humanize(overview.database)}</dd></div><div><dt>Diagnostic</dt><dd>{humanize(overview.database_detail)}</dd></div><div><dt>Write policy</dt><dd>Blocked / fail closed</dd></div></dl>
      <ol>
        <li><span>01</span><p><strong>Check configuration</strong> Confirm the private database URL exists in the ignored environment file.</p></li>
        <li><span>02</span><p><strong>Verify migration</strong> Ensure the `foundry` schema is current before accepting traffic.</p></li>
        <li><span>03</span><p><strong>Restore and rerun</strong> Reload this workspace, then start a new evidence run.</p></li>
      </ol>
    </section>
  );
}

function PanelHeading({ code, title, aside, id }: { code: string; title: string; aside: React.ReactNode; id: string }) {
  return <header className="panel-heading"><div><p>{code}</p><h2 id={id}>{title}</h2></div>{aside}</header>;
}

function EmptyPanel({ title, body }: { title: string; body: string }) {
  return <div className="empty-panel"><span aria-hidden="true" /><div><strong>{title}</strong><p>{body}</p></div></div>;
}

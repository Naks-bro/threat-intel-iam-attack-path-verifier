import type { FoundryOverview, RuleDetail } from "./foundry-api";
import { EvidencePanel, PipelinePanel, PrimitivesPanel, RulePanel, SourcesPanel, StatusTag } from "./FoundryPanels";
import type { FoundryPage } from "./foundry-navigation";
import { InvestigationPage } from "./InvestigationPage";

export function FoundryPageContent({ page, overview, rule, onOpen }: {
  page: FoundryPage; overview: FoundryOverview; rule: RuleDetail | null;
  onOpen: (versionId: string) => void;
}) {
  switch (page) {
    case "investigate": return <InvestigationPage />;
    case "overview": return <div className="operations-grid"><PipelinePanel overview={overview} rule={rule} /><OperationsBrief overview={overview} rule={rule} /></div>;
    case "pipeline": return <div className="operations-grid"><PipelinePanel overview={overview} rule={rule} /><section className="control-panel"><p className="section-code">RUN VISIBILITY</p><h2>Latest source outcomes</h2><p className="page-note">These are the latest source statuses, not a historical attempt timeline. No retry ancestry is exposed by this API yet.</p><SourceOutcomes overview={overview} /><p className="page-note">Runs are bounded and operator-triggered. An always-on scheduler is not configured.</p><a className="workspace-link" href="#/sources">Inspect source versions <span aria-hidden="true">↗</span></a></section></div>;
    case "sources": return <SourcesPanel sources={overview.sources} previewMode={overview.storage === "preview"} />;
    case "primitives": return <PrimitivesPanel primitives={overview.primitives} />;
    case "evidence": return <EvidencePanel relations={overview.relations} />;
    case "rules": return <RulePanel overview={overview} rule={rule} onOpen={onOpen} />;
    case "architecture": return <ArchitecturePage />;
  }
}

function SourceOutcomes({ overview }: { overview: FoundryOverview }) {
  return overview.sources.length ? <ul className="source-outcomes">{overview.sources.map((source) => <li key={source.source_key}><code>{source.source_key}</code><StatusTag value={source.last_status ?? "not_run"} /></li>)}</ul> : <p className="page-note">No source outcomes available.</p>;
}

function OperationsBrief({ overview, rule }: { overview: FoundryOverview; rule: RuleDetail | null }) {
  const required = rule?.validations.filter((check) => !check.optional) ?? [];
  const passes = required.filter((check) => check.result === "pass").length;
  const unmapped = overview.primitives.filter((primitive) => primitive.attack_mapping_state !== "mapped").length;
  const optionalMissing = rule?.validations.filter((check) => check.optional && check.result === "unavailable").length ?? 0;
  return <section className="control-panel operations-brief" aria-labelledby="brief-title">
    <p className="section-code">OPERATOR BRIEF / CURRENT STATE</p><h2 id="brief-title">Assurance &amp; attention</h2>
    <dl className="brief-metrics">
      <div><dt>Required deterministic checks</dt><dd>{passes}/{required.length}</dd></div>
      <div><dt>Unmapped primitives</dt><dd>{unmapped}</dd></div>
      <div><dt>Unavailable optional tools</dt><dd>{optionalMissing}</dd></div>
      <div><dt>Stable publication</dt><dd>{rule?.publication?.channel === "stable" ? "Present" : "None for selected rule"}</dd></div>
    </dl>
    <p className="page-note">{rule?.ai_verification?.provider === "fake" ? "The verifier is a schema-only test harness. No external model has reviewed this candidate." : rule?.ai_verification ? "Inspect the selected candidate for its recorded verifier result." : "No verifier result is available."}</p>
    <div className="workspace-links">
      <a className="workspace-link" href="#/rules">Open rule dossier <span aria-hidden="true">↗</span></a>
      <a className="workspace-link" href="#/primitives">Inspect mapping gaps <span aria-hidden="true">↗</span></a>
      <a className="workspace-link" href="#/architecture">Inspect delivery boundaries <span aria-hidden="true">↗</span></a>
    </div>
  </section>;
}

const ARCHITECTURE_STAGES = [
  { title: "Pinned source artifacts", state: "Implemented", detail: "MITRE taxonomy · AWS action vocabulary · redacted Stratus behavior metadata", boundary: "Untrusted source data" },
  { title: "Normalization & typed evidence", state: "Implemented", detail: "Source-specific adapters, integrity hashes, entities, claims, and relations", boundary: "Deterministic extraction" },
  { title: "Closed ontology & compiler", state: "Partial", detail: "Additional-credentials family compiled. Trust backdoor and service escalation still open.", boundary: "Canonical rule authorship" },
  { title: "Quality gate & scenario corpus", state: "Partial", detail: "Required checks and six credential cases. Four optional tools unavailable.", boundary: "Bounded local validation" },
  { title: "Evidence-grounded AI critic", state: "Partial", detail: "Version-bound result contract and fake harness. No real-model adapter configured.", boundary: "No rule mutation or execution" },
  { title: "Exact-version human review", state: "Planned", detail: "Durable decision bound to rule version, evidence hash, and approval scope", boundary: "Human release authority" },
  { title: "Stable publication enforcement", state: "Planned", detail: "Quality policy plus exact-version approval before stable Engine 3 export", boundary: "Fail-closed publication" },
] as const;

export function ArchitecturePage() {
  return <div className="architecture-page">
    <figure className="control-panel architecture-diagram" aria-label="Engine 1 evidence-to-rule architecture">
      <figcaption id="architecture-caption"><p className="section-code">RESEARCH STAGE 1 / ENGINE 01</p><h2>Engine 1 evidence-to-rule architecture</h2><p className="page-note">Arrows describe the target flow. Status labels describe the current code; they do not imply runtime connectivity.</p></figcaption>
      <ol className="architecture-flow">{ARCHITECTURE_STAGES.map((stage, index) => <li key={stage.title} className={`architecture-node is-${stage.state.toLowerCase()}`}><span className="architecture-step">{String(index + 1).padStart(2, "0")}</span><div><span className="architecture-boundary">{stage.boundary}</span><h3>{stage.title}</h3><p>{stage.detail}</p></div><span className="architecture-state">{stage.state}</span></li>)}</ol>
      <div className="architecture-storage"><strong>FastAPI ↔ PostgreSQL registry</strong><span>SQLAlchemy · Psycopg · Alembic. Persistence code exists; this preview runs entirely in memory. Current managed-database durability remains unverified.</span></div>
    </figure>
    <section className="control-panel" aria-labelledby="integration-title"><p className="section-code">RESEARCH STAGE 2 / CONTRACT HANDOFFS</p><h2 id="integration-title">Future engine integration</h2><div className="engine-handoffs">
      <article><span>ENGINE 02</span><h3>IAM state graph</h3><code>IAMGraphSnapshot</code><p>Synthetic normalization exists. Live read-only AWS collection and Neo4j persistence are not implemented.</p></article>
      <article><span>ENGINE 03</span><h3>Attack-path verification</h3><code>ApprovedRule + IAMGraphSnapshot</code><p>Local fixture matching and bounded traversal exist. Policy simulation and mapped sandbox verification are not implemented.</p></article>
      <article><span>ENGINE 04</span><h3>Decision support</h3><code>VerificationResult → Finding</code><p>Fixture-based explanations and baseline ranking exist. Ranking is not verification proof.</p></article>
    </div><p className="page-note">Cross-engine contracts remain Proposed v0.1. Foundry stable export is still planned. Preview candidates never enter Engine 3.</p></section>
  </div>;
}

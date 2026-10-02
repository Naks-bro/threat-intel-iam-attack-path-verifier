import { useState } from "react";

export type FoundryOverview = {
  database: string;
  database_detail: string;
  storage: string;
  registry: "unavailable" | "empty" | "ready" | "partial";
  sources: Array<{
    source_key: string;
    authority_tier: number;
    source_type: string;
    version_label: string;
    enabled: boolean;
    last_status?: string;
  }>;
  run: {
    status: string;
    fetched_count: number;
    created_count: number;
    unchanged_count: number;
    rejected_count: number;
    parser_version: string;
  } | null;
  primitives: Array<{
    primitive_key: string;
    outcome_category: string;
    required_actions: string[];
    attack_mapping_state: string;
    state_transition: string;
  }>;
  relations: Array<{
    from_native_id: string;
    to_native_id: string;
    relation_type: string;
    review_state: string;
    rationale: string;
  }>;
  candidates: Array<{
    rule_id: string;
    version_id: string;
    semantic_hash: string;
    lifecycle: string;
    channel: string;
  }>;
};

export type RuleDetail = {
  rule_id: string;
  semantic_hash: string;
  lifecycle: string;
  validations: Array<{ validator_name: string; result: string }>;
  ai_verification: { provider: string; model: string; verdict: string } | null;
  publication: { channel: string } | null;
  scenarios: Array<{ scenario_id: string; expect: string; result: string }>;
};

const NAV = [
  "Overview",
  "Sources",
  "Runs",
  "Knowledge",
  "Primitives",
  "Candidates",
  "Rule",
  "Evaluation",
] as const;

export type SectionName = (typeof NAV)[number];

export function FoundryScreen({
  overview,
  rule,
  notice,
  onRun,
  onOpen,
}: {
  overview: FoundryOverview;
  rule: RuleDetail | null;
  notice: string;
  onRun: () => void;
  onOpen: (versionId: string) => void;
}) {
  const [section, setSection] = useState<SectionName>("Overview");
  const stored = overview.storage === "postgres";
  function openCandidate(versionId: string) {
    setSection("Rule");
    onOpen(versionId);
  }
  return (
    <div className="shell">
      <aside>
        <p className="brand">Foundry</p>
        <nav>
          {NAV.map((item) => (
            <button
              key={item}
              type="button"
              className={item === section ? "nav active" : "nav"}
              onClick={() => setSection(item)}
            >
              {item}
            </button>
          ))}
        </nav>
      </aside>
      <main>
        <header>
          <div>
            <h1>Threat-to-rule foundry</h1>
            <p className="muted">Automated evidence, deterministic compile, experimental publication.</p>
          </div>
          <p className={stored ? "badge ok" : "badge"}>
            {stored ? "Stored in PostgreSQL" : `Not stored. Database ${overview.database_detail}`}
          </p>
        </header>
        <RegistryState overview={overview} />
        <Section name={section} overview={overview} rule={rule} onOpen={openCandidate} />
        <p>
          <button type="button" onClick={onRun}>
            Run pipeline
          </button>
        </p>
        {notice ? <p className="notice">{notice}</p> : null}
      </main>
    </div>
  );
}

function RegistryState({ overview }: { overview: FoundryOverview }) {
  if (overview.registry === "unavailable") {
    return <p className="notice">Database unavailable. The registry was not read.</p>;
  }
  if (overview.registry === "empty") {
    return <p>No sources ingested yet.</p>;
  }
  if (overview.run?.status === "partial") {
    return <p className="notice">Partial run. One source failed and was left uningested.</p>;
  }
  return null;
}

function Section({
  name,
  overview,
  rule,
  onOpen,
}: {
  name: SectionName;
  overview: FoundryOverview;
  rule: RuleDetail | null;
  onOpen: (versionId: string) => void;
}) {
  if (overview.registry === "unavailable" || overview.registry === "empty") {
    return null;
  }
  if (name === "Sources") {
    return (
      <table>
        <thead>
          <tr>
            <th>Source</th>
            <th>Tier</th>
            <th>Type</th>
            <th>Version</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {overview.sources.map((source) => (
            <tr key={source.source_key}>
              <td>{source.source_key}</td>
              <td>{source.authority_tier}</td>
              <td>{source.source_type}</td>
              <td>{source.version_label}</td>
              <td>{source.last_status ?? "unknown"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }
  if (name === "Runs") {
    if (!overview.run) {
      return <p>No pipeline run is stored.</p>;
    }
    return (
      <p>
        Status {overview.run.status}. Fetched {overview.run.fetched_count}. Created{" "}
        {overview.run.created_count}. Unchanged {overview.run.unchanged_count}. Rejected{" "}
        {overview.run.rejected_count}. Parser {overview.run.parser_version}.
      </p>
    );
  }
  if (name === "Knowledge") {
    return (
      <table>
        <thead>
          <tr>
            <th>From</th>
            <th>Relation</th>
            <th>To</th>
            <th>State</th>
          </tr>
        </thead>
        <tbody>
          {overview.relations.map((relation) => (
            <tr key={`${relation.from_native_id}-${relation.relation_type}-${relation.to_native_id}`}>
              <td>{relation.from_native_id}</td>
              <td>{relation.relation_type}</td>
              <td>{relation.to_native_id}</td>
              <td>{relation.review_state}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }
  if (name === "Primitives") {
    return (
      <table>
        <thead>
          <tr>
            <th>Primitive</th>
            <th>Outcome</th>
            <th>Actions</th>
            <th>ATT&CK</th>
          </tr>
        </thead>
        <tbody>
          {overview.primitives.map((primitive) => (
            <tr key={primitive.primitive_key}>
              <td>{primitive.primitive_key}</td>
              <td>{primitive.outcome_category}</td>
              <td>{primitive.required_actions.join(", ")}</td>
              <td>{primitive.attack_mapping_state}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }
  if (name === "Candidates") {
    if (overview.candidates.length === 0) {
      return <p>No candidates have been compiled.</p>;
    }
    return (
      <ul>
        {overview.candidates.map((candidate) => (
          <li key={candidate.version_id}>
            <button type="button" onClick={() => onOpen(candidate.version_id)}>
              {candidate.rule_id}
            </button>
            <span> {candidate.lifecycle}</span>
            <span> {candidate.channel}</span>
          </li>
        ))}
      </ul>
    );
  }
  if (name === "Rule") {
    if (!rule) {
      return <p>Select a candidate.</p>;
    }
    return (
      <section>
        <h2>{rule.rule_id}</h2>
        <p>Lifecycle {rule.lifecycle}.</p>
        <p className="muted">{rule.semantic_hash}</p>
        <ul>
          {rule.validations.map((item) => (
            <li key={item.validator_name}>
              {item.validator_name}: {item.result}
            </li>
          ))}
        </ul>
        <p>
          AI {rule.ai_verification?.provider ?? "none"}/{rule.ai_verification?.model ?? "none"}:{" "}
          {rule.ai_verification?.verdict ?? "absent"}
        </p>
        <p>Channel {rule.publication?.channel ?? "unpublished"}.</p>
        <ul>
          {rule.scenarios.map((scenario) => (
            <li key={scenario.scenario_id}>
              {scenario.scenario_id}: {scenario.expect} {scenario.result}
            </li>
          ))}
        </ul>
      </section>
    );
  }
  if (name === "Evaluation") {
    return <p>Corpus results are on the rule detail. This slice measures one credential family.</p>;
  }
  return (
    <section>
      <h2>Overview</h2>
      <p>
        {overview.sources.length} sources. {overview.primitives.length} primitives. Candidates{" "}
        {overview.candidates.length}.
      </p>
      <p>{overview.primitives.map((item) => item.primitive_key).join(", ")}</p>
      {overview.candidates.map((candidate) => (
        <p key={candidate.version_id}>
          <button type="button" onClick={() => onOpen(candidate.version_id)}>
            {candidate.rule_id}
          </button>
        </p>
      ))}
    </section>
  );
}

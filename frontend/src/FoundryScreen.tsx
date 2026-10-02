import { useState } from "react";

export type FoundryOverview = {
  persisted: boolean;
  storage: string;
  database: string;
  database_detail: string;
  sources: Array<{
    source_key: string;
    authority_tier: number;
    source_type: string;
    version_label: string;
    enabled: boolean;
  }>;
  run: {
    status: string;
    fetched_count: number;
    created_count: number;
    unchanged_count: number;
    rejected_count: number;
    parser_version: string;
  };
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
  candidate: {
    rule_id: string;
    semantic_hash: string;
    lifecycle: string;
  } | null;
  validations: Array<{ validator_name: string; result: string }>;
  ai_verification: { provider: string; model: string; verdict: string };
  publication: { channel: string; rule_id: string } | null;
  evaluation: {
    corpus_version: string;
    candidate_precision: number;
    candidate_recall: number;
    false_positive_rate: number;
    ai_verdict: string;
    ai_ablation: string;
  };
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
  notice,
  onRun,
}: {
  overview: FoundryOverview;
  notice: string;
  onRun: () => void;
}) {
  const [section, setSection] = useState<SectionName>("Overview");
  const stored = overview.storage === "postgres";
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
        <Section name={section} overview={overview} />
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

function Section({ name, overview }: { name: SectionName; overview: FoundryOverview }) {
  if (name === "Sources") {
    return (
      <table>
        <thead>
          <tr>
            <th>Source</th>
            <th>Tier</th>
            <th>Type</th>
            <th>Version</th>
          </tr>
        </thead>
        <tbody>
          {overview.sources.map((source) => (
            <tr key={source.source_key}>
              <td>{source.source_key}</td>
              <td>{source.authority_tier}</td>
              <td>{source.source_type}</td>
              <td>{source.version_label}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }
  if (name === "Runs") {
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
  if (name === "Candidates" || name === "Rule") {
    return (
      <section>
        <h2>{overview.candidate?.rule_id ?? "No candidate"}</h2>
        <p>Lifecycle {overview.candidate?.lifecycle ?? "none"}.</p>
        <p className="muted">{overview.candidate?.semantic_hash}</p>
        <ul>
          {overview.validations.map((item) => (
            <li key={item.validator_name}>
              {item.validator_name}: {item.result}
            </li>
          ))}
        </ul>
        <p>
          AI {overview.ai_verification.provider}/{overview.ai_verification.model}:{" "}
          {overview.ai_verification.verdict}
        </p>
        <p>Channel {overview.publication?.channel ?? "unpublished"}.</p>
      </section>
    );
  }
  if (name === "Evaluation") {
    return (
      <p>
        Corpus {overview.evaluation.corpus_version}. Precision {overview.evaluation.candidate_precision}.
        Recall {overview.evaluation.candidate_recall}. False-positive rate{" "}
        {overview.evaluation.false_positive_rate}. AI ablation {overview.evaluation.ai_ablation}.
      </p>
    );
  }
  return (
    <section>
      <h2>Overview</h2>
      <p>
        {overview.sources.length} sources. {overview.primitives.length} primitives. Candidate{" "}
        {overview.candidate?.rule_id ?? "none"}. Publication {overview.publication?.channel ?? "none"}.
      </p>
      <p>{overview.primitives.map((item) => item.primitive_key).join(", ")}</p>
    </section>
  );
}

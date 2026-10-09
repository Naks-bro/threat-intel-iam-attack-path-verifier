// Generated from QualityReport.model_json_schema(); do not edit by hand.

export type QualityFinding = {
  code: string;
  message: string;
  severity: "info" | "warning" | "error";
  evidence_refs?: Array<string>;
};

export type QualityReport = {
  schema_version?: "0.1";
  report_version?: "foundry-quality-0.1";
  report_id: string;
  report_hash: string;
  rule_version_id: string;
  rule_semantic_hash: string;
  evidence_snapshot_hash: string;
  status: "pass" | "fail" | "needs_review" | "incomplete";
  required_passed: number;
  required_total: number;
  optional_unavailable: number;
  stages: Array<QualityStage>;
};

export type QualityScenario = {
  scenario_id: string;
  case_class?: "positive" | "near_negative" | "missing_context" | "adversarial" | null;
  expect: "match" | "no_match" | "inconclusive";
  actual: "match" | "no_match" | "inconclusive";
  result: "pass" | "fail";
};

export type QualityStage = {
  stage_id: string;
  validator_version: string;
  corpus_version?: string | null;
  status: "pass" | "fail" | "unavailable" | "error" | "skipped";
  required: boolean;
  duration_ms?: number | null;
  findings?: Array<QualityFinding>;
  scenarios?: Array<QualityScenario>;
  evidence_refs?: Array<string>;
};

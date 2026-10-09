// Generated from ReviewState.model_json_schema(); do not edit by hand.

export type ReviewCommand = {
  request_id: string;
  rule_version_id: string;
  rule_semantic_hash: string;
  evidence_snapshot_hash: string;
  quality_report_hash: string;
  verifier_request_hash: string;
  verifier_response_hash: string;
  scope: "read_only_account_analysis" | "isolated_lab_validation" | "synthetic_benchmark";
  decision: "approved" | "rejected" | "revision_requested";
  comment?: string;
};

export type ReviewRecord = {
  schema_version?: "0.1";
  decision_id: string;
  command: ReviewCommand;
  reviewer_alias: string;
  identity_boundary?: "local_operator_alias";
  decided_at: string;
  record_hash: string;
};

export type ReviewState = {
  schema_version?: "0.1";
  rule_version_id: string;
  scope: "read_only_account_analysis" | "isolated_lab_validation" | "synthetic_benchmark";
  latest: ReviewRecord | null;
  release_eligibility?: "not_evaluated";
};

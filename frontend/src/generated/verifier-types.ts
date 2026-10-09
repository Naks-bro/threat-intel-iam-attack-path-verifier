// Generated from VerifierRecordSummary.model_json_schema(); do not edit by hand.

export type VerifierEvidenceSummary = {
  evidence_id: string;
  source_key: "mitre-attack" | "aws-service-reference" | "stratus-red-team";
  source_version: string;
  content_hash: string;
};

export type VerifierRecordSummary = {
  packet_id: string;
  pipeline_run_id: string;
  recorded_at: string;
  rule_version_id: string;
  rule_semantic_hash: string;
  evidence_snapshot_hash: string;
  request_hash: string;
  response_hash: string;
  provider: string;
  model: string;
  prompt_version: string;
  ontology_version: string;
  verdict: "pass" | "needs_review" | "reject";
  findings: Array<string>;
  citations: Array<string>;
  evidence: Array<VerifierEvidenceSummary>;
};

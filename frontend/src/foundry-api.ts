export type FoundrySource = {
  source_key: string;
  authority_tier: number;
  source_type: string;
  version_label: string;
  enabled: boolean;
  last_status?: string;
};

export type FoundryOverview = {
  schema_version?: string;
  database: string;
  database_detail: string;
  storage: string;
  registry: "unavailable" | "empty" | "ready" | "partial";
  sources: FoundrySource[];
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
  verifier_record?: VerifierRecordSummary | null;
  quality_report?: QualityReport | null;
  rule_id: string;
  version_id?: string;
  semantic_hash: string;
  lifecycle: string;
  rule?: {
    title?: string;
    description?: string;
    severity?: string;
    technique_refs?: Array<{ external_id?: string }>;
    evidence_refs?: string[];
    limitations?: string[];
  };
  validations: Array<{ validator_name: string; result: string; optional?: boolean; findings?: string[] }>;
  ai_verification: { provider: string; model: string; verdict: string } | null;
  publication: { channel: string } | null;
  scenarios: Array<{
    scenario_id: string;
    case_class?: string | null;
    expect: string;
    actual?: string | null;
    result: string;
  }>;
};

type ApiErrorBody = { detail?: unknown };

export class FoundryApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;

  constructor(status: number, code: string, requestId: string | null) {
    super(code);
    this.name = "FoundryApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

export type ApiResult<T> = { data: T; requestId: string | null };

async function requestJson<T>(path: string, init?: RequestInit): Promise<ApiResult<T>> {
  const response = await fetch(path, init);
  const requestId = response.headers.get("X-Request-ID");
  if (!response.ok) {
    let code = `http_${response.status}`;
    try {
      const body = (await response.json()) as ApiErrorBody;
      if (typeof body.detail === "string") {
        code = body.detail;
      }
    } catch {
      // An invalid error body is still represented by its HTTP status.
    }
    throw new FoundryApiError(response.status, code, requestId);
  }
  return { data: (await response.json()) as T, requestId };
}

export function getFoundryOverview(signal?: AbortSignal): Promise<ApiResult<FoundryOverview>> {
  return requestJson<FoundryOverview>("/v1/foundry/overview", { signal });
}

export async function getFoundryRule(
  versionId: string,
  signal?: AbortSignal,
): Promise<ApiResult<RuleDetail | null>> {
  try {
    return await requestJson<RuleDetail>(`/v1/foundry/rules/${encodeURIComponent(versionId)}`, {
      signal,
    });
  } catch (error) {
    if (error instanceof FoundryApiError && error.status === 404) {
      return { data: null, requestId: error.requestId };
    }
    throw error;
  }
}

export function runFoundryPipeline(): Promise<ApiResult<FoundryOverview>> {
  return requestJson<FoundryOverview>("/v1/foundry/runs", { method: "POST" });
}

export type CredentialAnalysis = {
  snapshot_id: string;
  graph_input_digest: string;
  start_node_id: string | null;
  input_rule_refs: Array<{ rule_id: string; rule_version: number }>;
  input_rule_digest: string;
  findings: Array<{
    finding_id: string;
    priority: string;
    summary: string;
    explanation: { why: string; evidence: string[]; verification_status: string };
    remediation: Array<{ proposal: string; requires_human_review: boolean }>;
  }>;
  attack_paths: Array<{
    start_node_id: string;
    goal_node_id: string;
    hops: Array<{ required_action: string; edge_id: string }>;
    rule_refs: Array<{ rule_id: string; rule_version: number }>;
  }>;
  verifications: Array<{
    status: string;
    limitations: string[];
    local_fixture: { missing_context: string[]; unsupported_conditions: string[] };
    policy_simulation: { status: string };
    sandbox: { status: string };
  }>;
  issues: Array<{ code: string; message: string }>;
};

export function analyzeCredentialFixture(startNodeId: string, signal?: AbortSignal): Promise<ApiResult<CredentialAnalysis>> {
  const query = new URLSearchParams({ start_node_id: startNodeId });
  return requestJson(`/v1/analyses/fixtures/credential_creation?${query}`, { method: "POST", signal });
}

export type RealAccountObservation = {
  data_kind: "real_account_observed";
  snapshot_digest: string;
  rule_version: number;
  rule_digest: string;
  authorization_evaluated: false;
  identities: Array<{
    key: string;
    label: string;
    outcome: "candidate_from_policy_text" | "no_matching_statement" | "unknown";
  }>;
};

export function getRealAccountObservation(signal?: AbortSignal): Promise<ApiResult<RealAccountObservation>> {
  return requestJson("/v1/observations/real-account-pair", { signal });
}

export type EdgeRemovalPreview = {
  original_snapshot_id: string;
  hypothetical_snapshot_id: string;
  removed_edge_id: string;
  baseline_candidate_paths: number;
  hypothetical_candidate_paths: number;
  disappeared_candidate_paths: number;
  appeared_candidate_paths: number;
  comparison_complete: boolean;
  limitation: string;
};

export function previewCredentialEdgeRemoval(
  edgeId: string,
  signal?: AbortSignal,
): Promise<ApiResult<EdgeRemovalPreview>> {
  return requestJson("/v1/analyses/fixtures/credential_creation/what-if", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ edge_id: edgeId }),
    signal,
  });
}
export function getReviewState(versionId: string, scope: ReviewCommand["scope"], signal?: AbortSignal): Promise<ApiResult<ReviewState>> {
  return requestJson(`/v1/foundry/rules/${encodeURIComponent(versionId)}/review?scope=${encodeURIComponent(scope)}`, { signal });
}

export function recordReview(command: ReviewCommand): Promise<ApiResult<ReviewRecord>> {
  return requestJson("/v1/foundry/reviews", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(command) });
}
import type { ReviewCommand, ReviewRecord, ReviewState } from "./generated/review-types";
import type { QualityReport } from "./generated/quality-types";
import type { VerifierRecordSummary } from "./generated/verifier-types";

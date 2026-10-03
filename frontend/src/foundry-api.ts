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
import type { QualityReport } from "./generated/quality-types";

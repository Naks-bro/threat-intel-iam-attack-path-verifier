import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { FoundryScreen, type FoundryOverview } from "./FoundryScreen";

const overview: FoundryOverview = {
  persisted: false,
  storage: "not_written",
  database: "unavailable",
  database_detail: "not_configured",
  sources: [
    {
      source_key: "mitre-attack",
      authority_tier: 1,
      source_type: "taxonomy",
      version_label: "19.2",
      enabled: true,
    },
  ],
  run: {
    status: "succeeded",
    fetched_count: 3,
    created_count: 3,
    unchanged_count: 0,
    rejected_count: 1,
    parser_version: "foundry-pin-parser-0.1",
  },
  primitives: [
    {
      primitive_key: "trust_policy_backdoor",
      outcome_category: "trust_modification",
      required_actions: ["iam:UpdateAssumeRolePolicy"],
      attack_mapping_state: "unmapped",
      state_transition: "trust edited",
    },
  ],
  relations: [],
  candidate: {
    rule_id: "rule_additional_cloud_credentials",
    semantic_hash: "sha256:abc",
    lifecycle: "validated",
  },
  validations: [{ validator_name: "schema", result: "pass" }],
  ai_verification: { provider: "fake", model: "schema-only", verdict: "pass" },
  publication: { channel: "experimental", rule_id: "rule_additional_cloud_credentials" },
  evaluation: {
    corpus_version: "iam-corpus-0.1",
    candidate_precision: 1,
    candidate_recall: 1,
    false_positive_rate: 0,
    ai_verdict: "pass",
    ai_ablation: "no_difference_on_this_corpus",
  },
};

describe("FoundryScreen", () => {
  it("shows the experimental candidate and the unmapped primitive", () => {
    render(<FoundryScreen overview={overview} notice="" onRun={() => undefined} />);
    expect(screen.getByText(/rule_additional_cloud_credentials/)).toBeTruthy();
    expect(screen.getByText(/trust_policy_backdoor/)).toBeTruthy();
    expect(screen.getByText(/Not stored/)).toBeTruthy();
    expect(screen.queryByText("attack-t1548-assume-chain")).toBeNull();
  });
});

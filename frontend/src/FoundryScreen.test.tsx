import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { FoundryScreen, type FoundryOverview, type RuleDetail } from "./FoundryScreen";

const overview: FoundryOverview = {
  database: "ok",
  database_detail: "reachable",
  storage: "postgres",
  registry: "ready",
  sources: [
    {
      source_key: "mitre-attack",
      authority_tier: 1,
      source_type: "taxonomy",
      version_label: "19.2",
      enabled: true,
      last_status: "succeeded",
    },
  ],
  run: {
    status: "partial",
    fetched_count: 4,
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
  candidates: [
    {
      rule_id: "rule_additional_cloud_credentials",
      version_id: "version_discovered",
      semantic_hash: "sha256:abc",
      lifecycle: "experimental",
      channel: "experimental",
    },
  ],
};

const rule: RuleDetail = {
  rule_id: "rule_additional_cloud_credentials",
  semantic_hash: "sha256:abc",
  lifecycle: "experimental",
  validations: [{ validator_name: "schema", result: "pass" }],
  ai_verification: { provider: "fake", model: "schema-only", verdict: "pass" },
  publication: { channel: "experimental" },
  scenarios: [{ scenario_id: "allow-create-access-key", expect: "match", result: "pass" }],
};

afterEach(() => cleanup());

describe("FoundryScreen", () => {
  it("shows the discovered candidate and the unmapped primitive", () => {
    render(
      <FoundryScreen overview={overview} rule={rule} notice="" onRun={() => undefined} onOpen={() => undefined} />,
    );
    expect(screen.getByText(/rule_additional_cloud_credentials/)).toBeTruthy();
    expect(screen.getByText(/trust_policy_backdoor/)).toBeTruthy();
    expect(screen.getByText(/Partial run/)).toBeTruthy();
    expect(screen.queryByText("attack-t1548-assume-chain")).toBeNull();
  });

  it("shows an unavailable registry without a candidate", () => {
    render(
      <FoundryScreen
        overview={{ ...overview, registry: "unavailable", storage: "not_written", candidates: [], primitives: [] }}
        rule={null}
        notice=""
        onRun={() => undefined}
        onOpen={() => undefined}
      />,
    );
    expect(screen.getByText(/Database unavailable/)).toBeTruthy();
    expect(screen.queryByText("rule_additional_cloud_credentials")).toBeNull();
  });
});

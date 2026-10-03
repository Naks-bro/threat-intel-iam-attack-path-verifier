import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { FoundryScreen, type FoundryOverview, type RuleDetail } from "./FoundryScreen";

const overview: FoundryOverview = {
  schema_version: "0.1",
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
  rule: {
    title: "Additional access key",
    evidence_refs: ["evidence_test_01"],
    limitations: ["Does not evaluate service control policies."],
  },
  validations: [
    { validator_name: "schema", result: "pass", optional: false, findings: [] },
    { validator_name: "condition_keys", result: "pass", optional: false, findings: ["This candidate declares no condition key"] },
    { validator_name: "access_analyzer", result: "unavailable", optional: true, findings: ["tool is not installed"] },
  ],
  ai_verification: { provider: "fake", model: "schema-only", verdict: "pass" },
  publication: { channel: "experimental" },
  scenarios: [{ scenario_id: "allow-create-access-key", expect: "match", result: "pass" }],
};

afterEach(() => {
  cleanup();
  window.history.replaceState(null, "", "/");
});

function renderWorkspace() {
  return render(<FoundryScreen overview={overview} rule={rule} notice={null}
    requestId={null} isRunning={false} onRun={() => undefined} onOpen={() => undefined} />);
}

describe("FoundryScreen", () => {
  it("shows source degradation and the rule verification dossier on its own page", () => {
    window.history.replaceState(null, "", "/#/rules");
    render(
      <FoundryScreen
        overview={overview}
        rule={rule}
        notice={null}
        requestId="request-test-01"
        isRunning={false}
        onRun={() => undefined}
        onOpen={() => undefined}
      />,
    );
    expect(screen.getAllByText(/rule_additional_cloud_credentials/)).toHaveLength(2);
    expect(screen.queryByText(/trust_policy_backdoor/)).toBeNull();
    expect(screen.getByText(/completed with source degradation/i)).toBeTruthy();
    expect(screen.getByText("Source integrity").parentElement?.textContent).toContain("1/1");
    expect(screen.getByText(/Verifier harness/)).toBeTruthy();
    expect(screen.getByText(/no external model called/i)).toBeTruthy();
    expect(screen.getByText("evidence_test_01")).toBeTruthy();
    expect(screen.getByText("Does not evaluate service control policies.")).toBeTruthy();
    expect(screen.getByText("This candidate declares no condition key")).toBeTruthy();
    expect(screen.getByText("tool is not installed")).toBeTruthy();
    expect(screen.getByText("1 optional tool unavailable")).toBeTruthy();
    expect(screen.getByRole("button", { name: /Run evidence pipeline/i })).toBeTruthy();
    expect(screen.getByText(/Trace request-test/i)).toBeTruthy();
    expect(screen.queryByText("attack-t1548-assume-chain")).toBeNull();
  });

  it("disables the run action while automation is executing", () => {
    render(
      <FoundryScreen
        overview={overview}
        rule={rule}
        notice={null}
        requestId={null}
        isRunning
        onRun={() => undefined}
        onOpen={() => undefined}
      />,
    );

    expect(screen.getByRole("button", { name: /Running evidence pipeline/i })).toHaveProperty(
      "disabled",
      true,
    );
  });

  it("shows an unavailable registry without a candidate", () => {
    render(
      <FoundryScreen
        overview={{ ...overview, registry: "unavailable", storage: "not_written", candidates: [], primitives: [] }}
        rule={null}
        notice={null}
        requestId="request-test-02"
        isRunning={false}
        onRun={() => undefined}
        onOpen={() => undefined}
      />,
    );
    expect(screen.getByText(/Registry evidence is unavailable/)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Run evidence pipeline/i })).toHaveProperty("disabled", true);
    expect(screen.queryByText("rule_additional_cloud_credentials")).toBeNull();
  });

  it("does not count a parked catalog as a failed active source", () => {
    window.history.replaceState(null, "", "/#/sources");
    render(
      <FoundryScreen
        overview={{
          ...overview,
          run: { ...overview.run!, status: "succeeded", fetched_count: 1 },
          sources: [
            ...overview.sources,
            {
              source_key: "aws-threat-technique-catalog",
              authority_tier: 1,
              source_type: "threat_catalog",
              version_label: "not_ingested",
              enabled: false,
              last_status: "disabled",
            },
          ],
        }}
        rule={rule}
        notice={null}
        requestId={null}
        isRunning={false}
        onRun={() => undefined}
        onOpen={() => undefined}
      />,
    );
    expect(screen.getByText("Source integrity").parentElement?.textContent).toContain("1/1");
    expect(screen.getByText("disabled")).toBeTruthy();
    expect(screen.queryByText(/completed with source degradation/i)).toBeNull();
  });

  it("labels the offline preview as non-persistent and non-published", () => {
    window.history.replaceState(null, "", "/#/rules");
    render(
      <FoundryScreen
        overview={{ ...overview, storage: "preview", database: "not_connected", database_detail: "offline_preview", run: { ...overview.run!, status: "succeeded" } }}
        rule={{ ...rule, publication: null }}
        notice={null}
        requestId={null}
        isRunning={false}
        onRun={() => undefined}
        onOpen={() => undefined}
      />,
    );
    expect(screen.getByText("OFFLINE PREVIEW")).toBeTruthy();
    expect(screen.getByText(/No Supabase connection, database writes, approval, or rule publication/)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Recompute preview/i })).toBeTruthy();
    expect(screen.getByText(/This candidate is not published or exported/)).toBeTruthy();
    expect(screen.queryByText("Registry degraded")).toBeNull();
  });

  it("keeps the overview focused and offers links to the detailed workspaces", () => {
    renderWorkspace();
    expect(screen.getByRole("heading", { level: 1, name: "Operations overview" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Scenario review" })).toBeNull();
    expect(screen.getByRole("link", { name: "Open rule dossier" }).getAttribute("href")).toBe("#/rules");
    expect(screen.getByRole("link", { name: "Overview" }).getAttribute("aria-current")).toBe("page");
  });

  it("responds to history navigation and focuses the new page heading", () => {
    renderWorkspace();
    window.history.pushState(null, "", "/#/primitives");
    fireEvent(window, new HashChangeEvent("hashchange"));
    const heading = screen.getByRole("heading", { level: 1, name: "Attack primitives" });
    expect(document.activeElement).toBe(heading);
    expect(screen.getByText("trust_policy_backdoor")).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Evidence pipeline" })).toBeNull();
    expect(screen.getByRole("link", { name: "Attack primitives" }).getAttribute("aria-current")).toBe("page");
  });

  it("makes planned architecture boundaries visible even without a registry", () => {
    window.history.replaceState(null, "", "/#/architecture");
    render(<FoundryScreen overview={{ ...overview, registry: "unavailable" }} rule={null}
      notice={null} requestId={null} isRunning={false} onRun={() => undefined} onOpen={() => undefined} />);
    expect(screen.getByRole("heading", { level: 1, name: "System architecture" })).toBeTruthy();
    expect(screen.getByRole("figure", { name: "Engine 1 evidence-to-rule architecture" })).toBeTruthy();
    expect(screen.getByText("Exact-version human review")).toBeTruthy();
    expect(screen.getByText("Stable publication enforcement")).toBeTruthy();
    expect(screen.getAllByText("Planned").length).toBeGreaterThan(0);
  });

  it("shows a recovery page for unknown routes instead of silently hiding the error", () => {
    window.history.replaceState(null, "", "/#/unknown");
    renderWorkspace();
    expect(screen.getByRole("heading", { level: 1, name: "Workspace not found" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Return to overview" })).toBeTruthy();
  });

  it("does not mark assurance complete when a required check fails", () => {
    window.history.replaceState(null, "", "/#/pipeline");
    render(<FoundryScreen overview={overview} rule={{ ...rule, validations: [
      { validator_name: "ontology", result: "fail", optional: false },
      { validator_name: "schema", result: "pass", optional: false },
    ] }} notice={null} requestId={null} isRunning={false} onRun={() => undefined} onOpen={() => undefined} />);
    expect(screen.getByText("1/2 required checks passed")).toBeTruthy();
    expect(screen.getByText("Assure").closest("li")?.textContent).toContain("needs review");
  });
});

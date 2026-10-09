import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import * as api from "./foundry-api";
import { InvestigationPage, type SealedPair } from "./InvestigationPage";

vi.mock("./foundry-api", async (importOriginal) => ({
  ...await importOriginal<typeof api>(),
  analyzeCredentialFixture: vi.fn(),
  getRealAccountObservation: vi.fn(),
}));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

function report(startNodeId: string, exposed: boolean): api.CredentialAnalysis {
  return {
    snapshot_id: "snapshot_paired_fixture",
    graph_input_digest: `sha256:${"c".repeat(64)}`,
    start_node_id: startNodeId,
    input_rule_refs: [{ rule_id: "rule_additional_cloud_credentials", rule_version: 1 }],
    input_rule_digest: `sha256:${"a".repeat(64)}`,
    findings: exposed ? [{
      finding_id: "finding_1", priority: "high", summary: "Candidate",
      explanation: { why: "Fixture path", evidence: ["policy_fixture_1"], verification_status: "supported_by_fixture" },
      remediation: [{ proposal: "Review this permission with the account owner.", requires_human_review: true }],
    }] : [],
    attack_paths: exposed ? [{
      start_node_id: startNodeId, goal_node_id: "principal:user/target",
      hops: [{ required_action: "iam:CreateAccessKey", edge_id: "edge_1" }],
      rule_refs: [{ rule_id: "rule_additional_cloud_credentials", rule_version: 1 }],
    }] : [],
    verifications: exposed ? [{
      status: "supported_by_fixture", limitations: ["No AWS authorization check"],
      local_fixture: { missing_context: [], unsupported_conditions: [] },
      policy_simulation: { status: "not_run" }, sandbox: { status: "not_mapped" },
    }] : [],
    issues: [],
  };
}

it("compares two synthetic identities and inspects only the selected one", async () => {
  vi.mocked(api.analyzeCredentialFixture).mockImplementation(async (id) => ({
    requestId: null, data: report(id, id.endsWith("developer")),
  }));
  render(<InvestigationPage />);
  expect(await screen.findByRole("heading", { name: "Timeline" })).toBeTruthy();
  expect(screen.getByRole("heading", { name: "Choose a starting identity" })).toBeTruthy();
  expect(screen.getByText(/No AWS account was scanned/)).toBeTruthy();
  expect(screen.getByRole("button", { name: "Developer, nexus event, iam:CreateAccessKey" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "Control user, on the timeline, no nexus event" })).toBeTruthy();
  expect(screen.getByRole("heading", { name: "No identity selected" })).toBeTruthy();

  fireEvent.click(screen.getByRole("button", { name: "Open nexus event from Developer to target" }));
  expect(screen.getByRole("heading", { name: "How the path works" })).toBeTruthy();
  expect(screen.getByRole("heading", { name: "Remove this permission edge?" })).toBeTruthy();
  expect(screen.getByText("policy_fixture_1")).toBeTruthy();

  fireEvent.click(screen.getByRole("button", { name: /Control comparator/ }));
  expect(screen.getByRole("heading", { name: "What this result does not say" })).toBeTruthy();
  expect(screen.getByText(/not a security certificate/)).toBeTruthy();
  expect(screen.queryByRole("heading", { name: "How the path works" })).toBeNull();
  expect(api.analyzeCredentialFixture).toHaveBeenCalledTimes(2);
});

it("refuses to compare different rule inputs", async () => {
  vi.mocked(api.analyzeCredentialFixture).mockImplementation(async (id) => {
    const data = report(id, id.endsWith("developer"));
    if (id.endsWith("control")) data.input_rule_digest = `sha256:${"b".repeat(64)}`;
    return { requestId: null, data };
  });
  render(<InvestigationPage />);
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("same graph and rule inputs"));
});

it("refuses to compare reused snapshot IDs with different graph bytes", async () => {
  vi.mocked(api.analyzeCredentialFixture).mockImplementation(async (id) => {
    const data = report(id, id.endsWith("developer"));
    if (id.endsWith("control")) data.graph_input_digest = `sha256:${"d".repeat(64)}`;
    return { requestId: null, data };
  });
  render(<InvestigationPage />);
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("same graph and rule inputs"));
});

it("refuses missing graph digests from an older or incomplete API", async () => {
  vi.mocked(api.analyzeCredentialFixture).mockImplementation(async (id) => {
    const data = report(id, id.endsWith("developer"));
    delete (data as Partial<api.CredentialAnalysis>).graph_input_digest;
    return { requestId: null, data };
  });
  render(<InvestigationPage />);
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("same graph and rule inputs"));
});

it("does not label an incomplete collection as a clean control", async () => {
  vi.mocked(api.analyzeCredentialFixture).mockImplementation(async (id) => {
    const data = report(id, id.endsWith("developer"));
    if (id.endsWith("control")) {
      data.issues = [{ code: "collection_incomplete", message: "Collection is incomplete." }];
    }
    return { requestId: null, data };
  });
  render(<InvestigationPage />);
  expect(await screen.findByRole("heading", { name: "Choose a starting identity" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /Control comparator/ }));
  expect(screen.getAllByText("Unknown / partial").length).toBeGreaterThan(0);
  expect(screen.getByRole("heading", { name: "Analysis limitations" })).toBeTruthy();
  expect(screen.getByText("Collection is incomplete.")).toBeTruthy();
  expect(screen.queryByText("No path for tested rule")).toBeNull();
});

it("fails closed when paths and evidence packets do not align", async () => {
  vi.mocked(api.analyzeCredentialFixture).mockImplementation(async (id) => {
    const data = report(id, id.endsWith("developer"));
    if (id.endsWith("developer")) data.verifications = [];
    return { requestId: null, data };
  });
  render(<InvestigationPage />);
  expect(await screen.findByRole("heading", { name: "Choose a starting identity" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /Exposed comparator/ }));
  expect(screen.getAllByText("Result incomplete").length).toBeGreaterThan(0);
  expect(screen.getByText(/unmatched paths, findings or verification records/)).toBeTruthy();
  expect(screen.queryByRole("heading", { name: "How the path works" })).toBeNull();
});

const sealedPair: SealedPair = {
  dataKind: "real_account_observed",
  snapshotDigest: `sha256:${"e".repeat(64)}`,
  ruleVersion: 1,
  ruleDigest: `sha256:${"f".repeat(64)}`,
  identities: [
    { key: "p_11111111111111111111111111111111", label: "user-00000001", outcome: "candidate_from_policy_text" },
    { key: "p_66666666666666666666666666666666", label: "user-00000006", outcome: "no_matching_statement" },
  ],
};

it("renders the sealed pair on the timeline as a real-account observation", async () => {
  vi.mocked(api.analyzeCredentialFixture).mockImplementation(async (id) => ({
    requestId: null, data: report(id, id.endsWith("developer")),
  }));
  render(<InvestigationPage sealedPair={sealedPair} />);
  expect(await screen.findByText(/Synthetic credential fixture/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Real-account observation" }));
  expect(screen.getByRole("heading", { name: "Timeline" })).toBeTruthy();
  expect(screen.getAllByText("Nexus event").length).toBeGreaterThan(0);
  expect(screen.getAllByText(/Real-account observation/).length).toBeGreaterThan(0);
  expect(screen.getAllByText(sealedPair.snapshotDigest).length).toBeGreaterThan(0);
  expect(screen.getAllByText(sealedPair.ruleDigest).length).toBeGreaterThan(0);
  expect(screen.getByRole("button", { name: "user-00000001, nexus event, iam:CreateAccessKey" })).toBeTruthy();
  const controlRows = screen.getAllByRole("button", { name: /user-00000006/ });
  const controlRow = controlRows.find((row) => (row.textContent ?? "").includes("No matching statement"));
  if (!controlRow) throw new Error("missing control row");
  expect(controlRow.textContent ?? "").not.toMatch(/secure/i);
  expect(screen.getByText(/local operator review is not authenticated authority and not exploit proof/i)).toBeTruthy();
  fireEvent.click(controlRow);
  expect(screen.getByText(/scoped observation, not a certificate/)).toBeTruthy();
  expect(screen.queryByText(/\bsecure\b/i)).toBeNull();
  expect(api.getRealAccountObservation).not.toHaveBeenCalled();
});

it("keeps an unknown sealed identity on the timeline without a nexus event", async () => {
  vi.mocked(api.analyzeCredentialFixture).mockResolvedValue({
    requestId: null,
    data: report("principal:user/developer", false),
  });
  const unknownPair: SealedPair = {
    ...sealedPair,
    identities: [
      { key: "p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", label: "user-00000001", outcome: "unknown" },
      { key: "p_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", label: "user-00000006", outcome: "unknown" },
    ],
  };
  render(<InvestigationPage sealedPair={unknownPair} />);
  fireEvent.click(await screen.findByRole("button", { name: "Real-account observation" }));
  expect(screen.getByRole("button", { name: "user-00000001, on the timeline, no nexus event" })).toBeTruthy();
  expect(screen.getAllByText("Unknown").length).toBeGreaterThan(0);
  expect(screen.queryByText("Nexus event")).toBeNull();
});

it("loads the sealed pair from the local observation and keeps the synthetic fixture", async () => {
  vi.mocked(api.analyzeCredentialFixture).mockImplementation(async (id) => ({
    requestId: null, data: report(id, id.endsWith("developer")),
  }));
  vi.mocked(api.getRealAccountObservation).mockResolvedValue({
    requestId: null,
    data: {
      data_kind: "real_account_observed",
      snapshot_digest: sealedPair.snapshotDigest,
      rule_version: sealedPair.ruleVersion,
      rule_digest: sealedPair.ruleDigest,
      authorization_evaluated: false,
      identities: [
        { key: "p_11111111111111111111111111111111", label: "user-00000001", outcome: "candidate_from_policy_text" },
        { key: "p_66666666666666666666666666666666", label: "user-00000006", outcome: "no_matching_statement" },
      ],
    },
  });
  render(<InvestigationPage />);
  expect(await screen.findByText(/Synthetic credential fixture/)).toBeTruthy();
  expect(api.analyzeCredentialFixture).toHaveBeenCalledTimes(2);
  fireEvent.click(screen.getByRole("button", { name: "Real-account observation" }));
  expect(await screen.findByText("Policy text only")).toBeTruthy();
  expect(screen.getByText(/Authorization was not evaluated/)).toBeTruthy();
  const comparison = screen.getAllByRole("button", { name: /user-00000006/ })
    .find((row) => (row.textContent ?? "").includes("No matching statement"));
  if (!comparison) throw new Error("missing comparison row");
  expect(comparison.textContent ?? "").not.toMatch(/secure/i);
  expect(api.analyzeCredentialFixture).toHaveBeenCalledTimes(2);
  fireEvent.click(screen.getByRole("button", { name: "Synthetic credential fixture" }));
  expect(await screen.findByText(/Synthetic credential fixture/)).toBeTruthy();
  expect(screen.getByRole("button", { name: /Exposed comparator/ })).toBeTruthy();
});

it("shows an honest empty state when no sealed snapshot is loaded", async () => {
  vi.mocked(api.analyzeCredentialFixture).mockResolvedValue({
    requestId: null,
    data: report("principal:user/developer", false),
  });
  vi.mocked(api.getRealAccountObservation).mockRejectedValue(
    new api.FoundryApiError(404, "sealed_observation_absent", null),
  );
  render(<InvestigationPage />);
  fireEvent.click(await screen.findByRole("button", { name: "Real-account observation" }));
  expect(await screen.findByText("No sealed snapshot is loaded in this session.")).toBeTruthy();
  expect(screen.queryByText(/\bsecure\b/i)).toBeNull();
});

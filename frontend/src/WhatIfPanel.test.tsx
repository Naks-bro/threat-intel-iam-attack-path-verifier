import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import * as api from "./foundry-api";
import { WhatIfPanel } from "./WhatIfPanel";

vi.mock("./foundry-api", async (importOriginal) => ({
  ...await importOriginal<typeof api>(),
  previewCredentialEdgeRemoval: vi.fn(),
}));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it("shows a synthetic structural delta without claiming an AWS change", async () => {
  vi.mocked(api.previewCredentialEdgeRemoval).mockResolvedValue({ requestId: null, data: {
    original_snapshot_id: "snapshot_original",
    hypothetical_snapshot_id: "whatif_123",
    removed_edge_id: "edge_create",
    baseline_candidate_paths: 1,
    hypothetical_candidate_paths: 0,
    disappeared_candidate_paths: 1,
    appeared_candidate_paths: 0,
    comparison_complete: true,
    limitation: "Structural preview only; not an AWS policy change.",
  } });
  render(<WhatIfPanel edgeId="edge_create" action="iam:CreateAccessKey" />);
  fireEvent.click(screen.getByRole("button", { name: "Preview edge removal" }));
  expect(await screen.findByText("1 original path(s) absent in the hypothetical graph.")).toBeTruthy();
  expect(screen.getByText("Structural preview only; not an AWS policy change.")).toBeTruthy();
  expect(api.previewCredentialEdgeRemoval).toHaveBeenCalledWith("edge_create", expect.any(AbortSignal));
});

it("keeps errors local to the comparison", async () => {
  vi.mocked(api.previewCredentialEdgeRemoval).mockRejectedValue(new Error("offline"));
  render(<WhatIfPanel edgeId="edge_create" action="iam:CreateAccessKey" />);
  fireEvent.click(screen.getByRole("button", { name: "Preview edge removal" }));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("original investigation was not changed"));
});

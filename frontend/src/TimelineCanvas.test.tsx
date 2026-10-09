import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { TimelineCanvas } from "./TimelineCanvas";

it("exposes a policy-text nexus event to the keyboard and keeps the timeline terms", () => {
  const onSelect = vi.fn();
  render(<TimelineCanvas
    snapshotId={`sha256:${"e".repeat(64)}`}
    selectedKey={null}
    onSelect={onSelect}
    stations={[
      {
        key: "first",
        label: "user-00000001",
        detail: "Candidate from policy text",
        nexus: {
          kind: "policy_text",
          action: "iam:CreateAccessKey",
          targetLabel: "Policy text",
          extraPaths: 0,
        },
      },
      {
        key: "second",
        label: "user-00000006",
        detail: "No matching statement",
        nexus: null,
      },
    ]}
  />);
  expect(screen.getByRole("heading", { name: "Timeline" })).toBeTruthy();
  expect(screen.getByText("Nexus event")).toBeTruthy();
  expect(screen.getByText("Nexus event, policy text only")).toBeTruthy();
  const branch = screen.getByRole("button", { name: "user-00000001, nexus event, iam:CreateAccessKey" });
  fireEvent.keyDown(branch, { key: "Enter" });
  fireEvent.keyDown(branch, { key: " " });
  expect(onSelect).toHaveBeenCalledTimes(2);
  expect(onSelect).toHaveBeenCalledWith("first");
  const control = screen.getByRole("button", { name: "user-00000006, on the timeline, no nexus event" });
  expect(control.textContent ?? "").not.toMatch(/secure/i);
});

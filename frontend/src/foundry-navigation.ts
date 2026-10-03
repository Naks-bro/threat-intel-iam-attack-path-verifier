import { useSyncExternalStore } from "react";

export const FOUNDRY_PAGES = [
  { key: "overview", label: "Overview", title: "Operations overview", icon: "overview", description: "Monitor evidence health, candidate assurance, and the boundaries of the current Engine 1 run." },
  { key: "pipeline", label: "Pipeline", title: "Pipeline operations", icon: "run", description: "Inspect the latest evidence computation and source outcomes. Run history and retry ancestry are still being developed." },
  { key: "sources", label: "Source intelligence", title: "Source intelligence", icon: "sources", description: "Inspect enabled inputs, pinned versions, and connector health. Disabled sources do not contribute to active source health." },
  { key: "primitives", label: "Attack primitives", title: "Attack primitives", icon: "primitives", description: "Review normalized IAM behaviors, required actions, and mapping gaps. A mapped behavior is not automatically a compiled rule." },
  { key: "evidence", label: "Evidence map", title: "Evidence relationships", icon: "evidence", description: "Inspect typed links and their rationale. Accepted evidence relations are distinct from human approval of a rule version." },
  { key: "rules", label: "Rule registry", title: "Rule assurance", icon: "verified", description: "Inspect immutable candidates, required checks, optional tools, scenarios, and known limitations before a release decision." },
  { key: "architecture", label: "Architecture", title: "System architecture", icon: "evidence", description: "Understand Stage 1, its trust boundaries, and the contracts for future engines. Planned components are labeled explicitly." },
] as const;

export type FoundryPage = typeof FOUNDRY_PAGES[number]["key"];

function subscribe(listener: () => void) {
  window.addEventListener("hashchange", listener);
  return () => window.removeEventListener("hashchange", listener);
}

function readPage(): FoundryPage | "not-found" {
  const hash = window.location.hash;
  if (!hash || hash === "#" || hash === "#/") return "overview";
  // Keep existing bookmarked panel anchors usable while new links use page routes.
  const key = hash.replace(/^#\/?/, "");
  return FOUNDRY_PAGES.find((page) => page.key === key)?.key ?? "not-found";
}

export function useFoundryPage() {
  return useSyncExternalStore(subscribe, readPage, () => "overview" as const);
}

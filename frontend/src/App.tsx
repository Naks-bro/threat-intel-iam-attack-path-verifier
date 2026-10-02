import { useEffect, useState } from "react";
import { FoundryScreen, type FoundryOverview, type RuleDetail } from "./FoundryScreen";

type LoadState =
  | { kind: "loading" }
  | { kind: "ready"; overview: FoundryOverview; rule: RuleDetail | null }
  | { kind: "failed"; message: string };

export function App() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [notice, setNotice] = useState("");

  async function loadRule(versionId: string): Promise<RuleDetail | null> {
    const response = await fetch(`/v1/foundry/rules/${versionId}`);
    if (!response.ok) {
      return null;
    }
    return (await response.json()) as RuleDetail;
  }

  async function load() {
    const response = await fetch("/v1/foundry/overview");
    if (!response.ok) {
      throw new Error("The foundry overview did not load.");
    }
    const overview = (await response.json()) as FoundryOverview;
    const first = overview.candidates[0];
    const rule = first ? await loadRule(first.version_id) : null;
    setState({ kind: "ready", overview, rule });
  }

  useEffect(() => {
    let cancelled = false;
    load().catch((error: unknown) => {
      if (!cancelled) {
        const message = error instanceof Error ? error.message : "The foundry overview did not load.";
        setState({ kind: "failed", message });
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  async function runPipeline() {
    setNotice("");
    const response = await fetch("/v1/foundry/runs", { method: "POST" });
    if (response.status === 503) {
      setNotice("Database unavailable. Nothing was saved.");
      return;
    }
    if (!response.ok) {
      setNotice("The run failed. Nothing new was published.");
      return;
    }
    const overview = (await response.json()) as FoundryOverview;
    const first = overview.candidates[0];
    const rule = first ? await loadRule(first.version_id) : null;
    setState({ kind: "ready", overview, rule });
    setNotice("Stored in PostgreSQL. The rule is experimental.");
  }

  async function openRule(versionId: string) {
    if (state.kind !== "ready") {
      return;
    }
    const rule = await loadRule(versionId);
    setState({ kind: "ready", overview: state.overview, rule });
  }

  if (state.kind === "loading") {
    return <p>Loading the foundry.</p>;
  }
  if (state.kind === "failed") {
    return <p className="notice bad">{state.message}</p>;
  }
  return (
    <FoundryScreen
      overview={state.overview}
      rule={state.rule}
      notice={notice}
      onRun={() => void runPipeline()}
      onOpen={(versionId) => void openRule(versionId)}
    />
  );
}

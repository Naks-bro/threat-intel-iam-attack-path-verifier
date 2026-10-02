import { useEffect, useState } from "react";
import { FoundryScreen, type FoundryOverview } from "./FoundryScreen";

type LoadState =
  | { kind: "loading" }
  | { kind: "ready"; overview: FoundryOverview }
  | { kind: "failed"; message: string };

export function App() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [notice, setNotice] = useState("");

  async function load() {
    const response = await fetch("/v1/foundry/overview");
    if (!response.ok) {
      throw new Error("The foundry overview did not load.");
    }
    setState({ kind: "ready", overview: (await response.json()) as FoundryOverview });
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
    setState({ kind: "ready", overview: (await response.json()) as FoundryOverview });
    setNotice("Stored in PostgreSQL. The rule is experimental.");
  }

  if (state.kind === "loading") {
    return <p>Loading the foundry.</p>;
  }
  if (state.kind === "failed") {
    return <p className="notice bad">{state.message}</p>;
  }
  return (
    <FoundryScreen overview={state.overview} notice={notice} onRun={() => void runPipeline()} />
  );
}

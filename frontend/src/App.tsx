import { useEffect, useState } from "react";
import {
  FoundryApiError,
  getFoundryOverview,
  getFoundryRule,
  runFoundryPipeline,
  type FoundryOverview,
  type RuleDetail,
} from "./foundry-api";
import { FoundryScreen, type FoundryNotice } from "./FoundryScreen";

type LoadState =
  | { kind: "loading" }
  | {
      kind: "ready";
      overview: FoundryOverview;
      rule: RuleDetail | null;
      requestId: string | null;
    }
  | { kind: "failed"; message: string; requestId: string | null };

function apiFailure(error: unknown, fallback: string): { message: string; requestId: string | null } {
  if (error instanceof FoundryApiError) {
    const message =
      error.code === "database_unavailable"
        ? "The registry database is unavailable. No foundry state was changed."
        : error.code === "foundry_run_in_progress"
          ? "Another evidence run is already in progress. Refresh the registry after it completes."
        : fallback;
    return { message, requestId: error.requestId };
  }
  return { message: error instanceof Error ? error.message : fallback, requestId: null };
}

export function App() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [notice, setNotice] = useState<FoundryNotice | null>(null);
  const [isRunning, setIsRunning] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      const overviewResult = await getFoundryOverview(controller.signal);
      const first = overviewResult.data.candidates[0];
      const ruleResult = first
        ? await getFoundryRule(first.version_id, controller.signal)
        : { data: null, requestId: overviewResult.requestId };
      setState({
        kind: "ready",
        overview: overviewResult.data,
        rule: ruleResult.data,
        requestId: ruleResult.requestId ?? overviewResult.requestId,
      });
    }
    load().catch((error: unknown) => {
      if (!controller.signal.aborted) {
        const failure = apiFailure(error, "The foundry control plane did not load.");
        setState({ kind: "failed", ...failure });
      }
    });
    return () => controller.abort();
  }, []);

  async function runPipeline() {
    if (isRunning) {
      return;
    }
    setIsRunning(true);
    setNotice(null);
    try {
      const overviewResult = await runFoundryPipeline();
      const first = overviewResult.data.candidates[0];
      const ruleResult = first
        ? await getFoundryRule(first.version_id)
        : { data: null, requestId: overviewResult.requestId };
      setState({
        kind: "ready",
        overview: overviewResult.data,
        rule: ruleResult.data,
        requestId: ruleResult.requestId ?? overviewResult.requestId,
      });
      setNotice({
        kind: "success",
        title: overviewResult.data.storage === "preview" ? "Preview recomputed" : "Evidence run stored",
        message: overviewResult.data.storage === "preview"
          ? "Pinned evidence was evaluated in memory. Nothing was stored or published."
          : "Experimental output remains isolated from Engine 3.",
        requestId: overviewResult.requestId,
      });
    } catch (error) {
      const failure = apiFailure(error, "The run failed. Nothing new was published.");
      setNotice({ kind: "error", title: "Run not stored", ...failure });
    } finally {
      setIsRunning(false);
    }
  }

  async function openRule(versionId: string) {
    if (state.kind !== "ready") {
      return;
    }
    try {
      const result = await getFoundryRule(versionId);
      setState({
        kind: "ready",
        overview: state.overview,
        rule: result.data,
        requestId: result.requestId ?? state.requestId,
      });
    } catch (error) {
      const failure = apiFailure(error, "The selected rule version did not load.");
      setNotice({ kind: "error", title: "Rule unavailable", ...failure });
    }
  }

  if (state.kind === "loading") {
    return (
      <main className="application-state" aria-busy="true" aria-label="Loading evidence foundry">
        <span className="loading-mark" aria-hidden="true" />
        <p>Opening evidence control</p>
      </main>
    );
  }
  if (state.kind === "failed") {
    return (
      <main className="application-state application-state-error" role="alert">
        <span className="state-code">CONTROL PLANE / UNAVAILABLE</span>
        <h1>Evidence control could not start</h1>
        <p>{state.message}</p>
        {state.requestId ? <code>Request {state.requestId}</code> : null}
        <button type="button" onClick={() => window.location.reload()}>Retry connection</button>
      </main>
    );
  }
  return (
    <FoundryScreen
      overview={state.overview}
      rule={state.rule}
      notice={notice}
      requestId={state.requestId}
      isRunning={isRunning}
      onRun={() => void runPipeline()}
      onOpen={(versionId) => void openRule(versionId)}
    />
  );
}

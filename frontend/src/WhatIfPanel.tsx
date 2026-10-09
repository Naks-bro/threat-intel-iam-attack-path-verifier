import { useEffect, useRef, useState } from "react";
import { previewCredentialEdgeRemoval, type EdgeRemovalPreview } from "./foundry-api";

type PreviewState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "error" }
  | { status: "ready"; result: EdgeRemovalPreview };

export function WhatIfPanel({ edgeId, action }: { edgeId: string; action: string }) {
  const [state, setState] = useState<PreviewState>({ status: "idle" });
  const controller = useRef<AbortController | null>(null);

  useEffect(() => () => controller.current?.abort(), []);

  function preview() {
    controller.current?.abort();
    controller.current = new AbortController();
    setState({ status: "loading" });
    previewCredentialEdgeRemoval(edgeId, controller.current.signal)
      .then(({ data }) => setState({ status: "ready", result: data }))
      .catch(() => {
        if (!controller.current?.signal.aborted) setState({ status: "error" });
      });
  }

  return <section className="control-panel what-if-panel" aria-labelledby="what-if-title">
    <p className="section-code">WHAT IF / SYNTHETIC ONLY</p>
    <h2 id="what-if-title">Remove this permission edge?</h2>
    <p>Preview a graph without the <code>{action}</code> edge. This does not edit a policy or your AWS account.</p>
    <button type="button" onClick={preview} disabled={state.status === "loading"}>
      {state.status === "loading" ? "Comparing…" : "Preview edge removal"}
    </button>
    {state.status === "error" && <p role="alert">The comparison is unavailable. The original investigation was not changed.</p>}
    {state.status === "ready" && <div className="what-if-result" role="status">
      <dl>
        <div><dt>Original candidate paths</dt><dd>{state.result.baseline_candidate_paths}</dd></div>
        <div><dt>Hypothetical candidate paths</dt><dd>{state.result.hypothetical_candidate_paths}</dd></div>
      </dl>
      <p>{state.result.disappeared_candidate_paths} original path(s) absent in the hypothetical graph.</p>
      {state.result.appeared_candidate_paths > 0 && <p>{state.result.appeared_candidate_paths} path(s) appeared under the search bounds.</p>}
      {!state.result.comparison_complete && <p>Search limits were hit; these counts are incomplete.</p>}
      <p className="page-note">{state.result.limitation}</p>
    </div>}
  </section>;
}

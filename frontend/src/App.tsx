import { useEffect, useState } from "react";

type WorkbenchView = {
  pin_id: string;
  technique_id: string;
  technique_name: string;
  official_reference: string;
  artifact_sha256: string;
  normalized_record_id: string;
  lifecycle: string;
  rule_id: string | null;
  rule_version: number | null;
  validation_status: string;
  explanation: string;
  limitations: string[];
  persisted: boolean;
  storage: string;
};

type Health = {
  database: string;
  database_detail: string;
};

type LoadState =
  | { kind: "loading" }
  | { kind: "ready"; view: WorkbenchView; health: Health }
  | { kind: "failed"; message: string };

export function App() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [importMessage, setImportMessage] = useState<string>("");
  const [importing, setImporting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const [healthResponse, viewResponse] = await Promise.all([
          fetch("/health"),
          fetch("/v1/workbench/fixtures/attack-t1548-assume-chain"),
        ]);
        if (!healthResponse.ok || !viewResponse.ok) {
          throw new Error("The workbench API did not return the pending review.");
        }
        const health = (await healthResponse.json()) as Health;
        const view = (await viewResponse.json()) as WorkbenchView;
        if (!cancelled) {
          setState({ kind: "ready", view, health });
        }
      } catch (error) {
        if (!cancelled) {
          const message = error instanceof Error ? error.message : "The review could not be loaded.";
          setState({ kind: "failed", message });
        }
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  async function importPin() {
    setImporting(true);
    setImportMessage("");
    try {
      const response = await fetch("/v1/workbench/imports/attack-t1548-assume-chain", {
        method: "POST",
      });
      if (response.status === 503) {
        setImportMessage("Database unavailable. Nothing was saved.");
        return;
      }
      if (!response.ok) {
        setImportMessage("Import failed. Nothing new was published.");
        return;
      }
      const view = (await response.json()) as WorkbenchView;
      setImportMessage(
        view.persisted
          ? "Stored in PostgreSQL. The candidate is still pending review."
          : "The response did not confirm a stored row.",
      );
    } catch {
      setImportMessage("Import request failed. Nothing was saved.");
    } finally {
      setImporting(false);
    }
  }

  return (
    <main className="app">
      <header>
        <div>
          <h1>CTI rule workbench</h1>
          <p className="muted">Pinned MITRE evidence through deterministic validation. Approval is still pending.</p>
        </div>
        {state.kind === "ready" ? (
          <p className={state.health.database === "ok" ? "badge ok" : "badge"}>
            Database {state.health.database}: {state.health.database_detail}
          </p>
        ) : null}
      </header>
      {state.kind === "loading" ? <p>Loading the pinned review.</p> : null}
      {state.kind === "failed" ? <p className="notice bad">{state.message}</p> : null}
      {state.kind === "ready" ? <Review view={state.view} /> : null}
      <p>
        <button type="button" onClick={() => void importPin()} disabled={importing || state.kind !== "ready"}>
          {importing ? "Importing" : "Import pinned artifact"}
        </button>
      </p>
      {importMessage ? <p className="notice">{importMessage}</p> : null}
    </main>
  );
}

function Review({ view }: { view: WorkbenchView }) {
  return (
    <>
      <ol className="stages">
        <li className="stage"><span>1</span><em>Raw artifact</em><strong>{view.pin_id}</strong></li>
        <li className="stage"><span>2</span><em>Normalized</em><strong>{view.technique_id}</strong></li>
        <li className="stage"><span>3</span><em>Candidate</em><strong>{view.rule_id ?? "unsupported"}</strong></li>
        <li className="stage"><span>4</span><em>Validation</em><strong>{view.validation_status}</strong></li>
        <li className="stage"><span>5</span><em>Review</em><strong>{view.lifecycle}</strong></li>
      </ol>
      <div className="columns">
        <section>
          <h2>Evidence</h2>
          <p>{view.technique_name}</p>
          <p><a href={view.official_reference}>{view.official_reference}</a></p>
          <p className="muted">{view.artifact_sha256}</p>
          <p className="muted">Record {view.normalized_record_id}</p>
        </section>
        <section>
          <h2>Candidate</h2>
          <p>{view.rule_id} version {view.rule_version ?? "none"}</p>
          <p>{view.explanation}</p>
        </section>
        <section>
          <h2>Validation</h2>
          <p>Status {view.validation_status}. Storage {view.storage}.</p>
          <ul>
            {view.limitations.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>
      </div>
    </>
  );
}

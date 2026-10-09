import { useEffect, useRef } from "react";
import type { FoundryOverview, RuleDetail } from "./foundry-api";
import {
  FoundryIcon,
  RegistryUnavailable,
  StatusTag,
} from "./FoundryPanels";
import { ArchitecturePage, FoundryPageContent } from "./FoundryPages";
import { FOUNDRY_PAGES, useFoundryPage } from "./foundry-navigation";

export type { FoundryOverview, RuleDetail } from "./foundry-api";

export type FoundryNotice = {
  kind: "success" | "error";
  title: string;
  message: string;
  requestId: string | null;
};

export function FoundryScreen({
  overview,
  rule,
  notice,
  requestId,
  isRunning,
  onRun,
  onOpen,
}: {
  overview: FoundryOverview;
  rule: RuleDetail | null;
  notice: FoundryNotice | null;
  requestId: string | null;
  isRunning: boolean;
  onRun: () => void;
  onOpen: (versionId: string) => void;
}) {
  const page = useFoundryPage();
  const pageInfo = FOUNDRY_PAGES.find((item) => item.key === page);
  const headingRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    document.title = `${pageInfo?.title ?? "Workspace not found"} · Evidence Foundry`;
    headingRef.current?.focus({ preventScroll: true });
  }, [pageInfo]);
  const sourceSucceeded = overview.sources.filter(
    (source) => source.enabled && source.last_status === "succeeded",
  ).length;
  const activeSources = overview.sources.filter((source) => source.enabled).length;
  const sourceFailed = overview.sources.filter((source) => source.enabled && source.last_status === "failed");
  const mappedPrimitives = overview.primitives.filter(
    (primitive) => primitive.attack_mapping_state === "mapped",
  ).length;
  const acceptedRelations = overview.relations.filter(
    (relation) => relation.review_state === "accepted",
  ).length;
  const registryAvailable = overview.registry !== "unavailable";
  const storageOnline = overview.storage === "postgres";
  const previewMode = overview.storage === "preview";

  return (
    <div className="foundry-shell">
      <a className="skip-link" href="#workspace-content" onClick={(event) => { event.preventDefault(); headingRef.current?.focus(); }}>Skip to page content</a>
      <aside className="product-rail">
        <a className="product-mark" href="#/overview" aria-label="IAM Evidence Foundry overview">
          <span className="product-symbol" aria-hidden="true">
            <span />
            <span />
            <span />
          </span>
          <span className="product-name">
            <strong>Evidence Foundry</strong>
            <small>One account · two identities</small>
          </span>
        </a>

        <nav aria-label="Foundry navigation">
          <p>Workspace</p>
          {FOUNDRY_PAGES.map((item) => (
            <a href={`#/${item.key}`} key={item.key} aria-current={page === item.key ? "page" : undefined}>
              <FoundryIcon name={item.icon} />
              <span>{item.label}</span>
            </a>
          ))}
        </nav>

        <div className="rail-scope">
          <p>Enforcement boundary</p>
          <strong>Human-gated release</strong>
          <span>AI can challenge evidence. It cannot author, approve, or publish rules.</span>
        </div>

        <div className="rail-health">
          <span className={`health-beacon ${storageOnline ? "is-online" : "is-offline"}`} />
          <div>
            <strong>{previewMode ? "Offline preview" : storageOnline ? "Registry connected" : "Registry degraded"}</strong>
            <span>{previewMode ? "Pinned evidence · no database" : "Private PostgreSQL schema"}</span>
          </div>
        </div>
      </aside>

      <main className="foundry-workspace" id="workspace-content">
        <div className="utility-bar">
          <span>Research control plane</span>
          <span className="utility-divider" aria-hidden="true" />
          <span>Schema {overview.schema_version ?? "0.1"}</span>
          <span className="utility-trace" title={requestId ?? undefined}>
            Trace {requestId ? requestId.slice(0, 12) : "not issued"}
          </span>
        </div>

        <header className="foundry-header">
          <div className="header-copy">
            <p className="section-code">{page === "investigate" ? "IAM ANALYSIS / SYNTHETIC BENCHMARK" : "EVIDENCE CONTROL / ENGINE 01"}</p>
            <h1 ref={headingRef} tabIndex={-1}>{pageInfo?.title ?? "Workspace not found"}</h1>
            <p>{pageInfo?.description ?? "This workspace address does not exist. Use the navigation to open a supported page."}</p>
            <div className="scope-list" aria-label="Foundry scope">
              <span>AWS IAM</span>
              <span>Evidence-backed</span>
              <span>Fail closed</span>
            </div>
          </div>
          <div className="header-control">
            <StatusTag value={previewMode ? "offline_preview" : overview.run?.status ?? overview.registry} />
            {page !== "investigate" ? <button
              className="primary-action"
              type="button"
              onClick={onRun}
              disabled={isRunning || !registryAvailable}
              aria-describedby={!registryAvailable ? "run-disabled-reason" : undefined}
            >
              <FoundryIcon name="run" />
              <span>{previewMode ? isRunning ? "Recomputing preview" : "Recompute preview" : isRunning ? "Running evidence pipeline" : "Run evidence pipeline"}</span>
            </button> : null}
            {!registryAvailable ? (
              <small id="run-disabled-reason">Restore the registry connection to run.</small>
            ) : null}
          </div>
        </header>

        {page === "overview" ? (
          <ol className="analyst-pass" aria-label="One analyst pass">
            <li><strong>This click</strong> Recompute the pinned evidence. Nothing is published.</li>
            <li><strong>Human gate</strong> A person accepts one exact rule version.</li>
            <li><strong>Timeline</strong> Compare two identities on one snapshot.</li>
            <li><strong>Nexus event</strong> A branch is a possibility. Unknown stays unknown.</li>
            <li><strong>Handoff</strong> IT receives a redacted report only after review.</li>
          </ol>
        ) : null}

        {previewMode && page !== "investigate" ? (
          <div className="preview-banner" role="status">
            <span className="preview-label">OFFLINE PREVIEW</span>
            <span>Pinned local evidence only. No Supabase connection, database writes, approval, or rule publication. Candidate results show eligibility, not a released rule.</span>
          </div>
        ) : null}

        {notice ? (
          <div className={`operation-notice is-${notice.kind}`} role="status" aria-live="polite">
            <FoundryIcon name={notice.kind === "success" ? "verified" : "alert"} />
            <div>
              <strong>{notice.title}</strong>
              <span>{notice.message}</span>
            </div>
            {notice.requestId ? <code>{notice.requestId}</code> : null}
          </div>
        ) : null}

        {overview.run?.status === "partial" ? (
          <div className="attention-strip" role="status">
            <span className="attention-index">ATTN</span>
            <strong>Evidence run completed with source degradation.</strong>
            <span>
              {sourceFailed.length || 1} connector needs attention; successful evidence remains
              preserved.
            </span>
          </div>
        ) : null}

        {page !== "investigate" ? <section className="posture-strip" aria-label="Foundry security posture">
          <article>
            <span>Source integrity</span>
            <strong>{sourceSucceeded}/{activeSources}</strong>
            <small>{previewMode ? "pinned sources loaded" : "active connectors healthy"}</small>
          </article>
          <article>
            <span>Evidence graph</span>
            <strong>{overview.relations.length}</strong>
            <small>{acceptedRelations} accepted relations</small>
          </article>
          <article>
            <span>Mapped behavior</span>
            <strong>{mappedPrimitives}/{overview.primitives.length || 0}</strong>
            <small>primitives mapped</small>
          </article>
          <article>
            <span>Release channel</span>
            <strong>{rule?.publication?.channel ?? "gated"}</strong>
            <small>{overview.candidates.length} immutable version</small>
          </article>
        </section> : null}

        {page === "not-found" ? (
          <section className="control-panel"><h2>Choose a supported workspace</h2><a className="workspace-link" href="#/overview">Return to overview</a></section>
        ) : page === "architecture" ? (
          <ArchitecturePage />
        ) : !registryAvailable && page !== "investigate" ? (
          <RegistryUnavailable overview={overview} />
        ) : (
          <FoundryPageContent page={page} overview={overview} rule={rule} onOpen={onOpen} />
        )}

        <footer className="product-footer">
          <span>Evidence Foundry / research prototype</span>
          <span>Live AWS writes disabled</span>
          <span>Experimental rules excluded from Engine 3 by default</span>
        </footer>
      </main>
    </div>
  );
}

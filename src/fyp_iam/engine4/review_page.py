"""Server-rendered local review pages. Finding text is escaped and never executed."""

from collections.abc import Sequence
from html import escape

from fyp_iam.contracts.models import ApprovedRule, AttackHop, IAMGraphSnapshot
from fyp_iam.core.report import AnalysisReport
from fyp_iam.engine1.catalog import CatalogRecord, SystemCatalog
from fyp_iam.engine1.dataset import CloudTechniqueDataset, CloudTechniqueRecord
from fyp_iam.engine1.models import NormalizedTechnique
from fyp_iam.engine4.manifest import LocalFixtureManifest

_PAGE_STYLE = """
body { font-family: Georgia, serif; margin: 2rem; color: #1c1917; background: #fafaf9; }
a { color: #1d4ed8; }
table { border-collapse: collapse; width: 100%; }
th, td { border-bottom: 1px solid #d6d3d1; text-align: left; padding: 0.4rem; }
section { border: 1px solid #d6d3d1; padding: 1rem; margin: 1rem 0; background: #fff; }
.badge { display: inline-block; padding: 0.1rem 0.4rem; border: 1px solid #44403c; }
"""


def escape_review_text(value: str) -> str:
    return escape(value, quote=True)


def render_review_index(rows: Sequence[tuple[str, str, str, str]]) -> str:
    """Render case id, verification status, priority, and baseline score."""
    body = "\n".join(
        "<tr data-status='{status}'>"
        "<td><a href='/reviews/fixtures/{case_id}'>{case_id}</a></td>"
        "<td>{status}</td><td>{priority}</td><td>{score}</td></tr>".format(
            case_id=escape_review_text(case_id),
            status=escape_review_text(status),
            priority=escape_review_text(priority),
            score=escape_review_text(score),
        )
        for case_id, status, priority, score in rows
    )
    return _document(
        "Local fixture review",
        f"""
        <p>Local fixtures only. AWS is not connected. The baseline score is not verification.</p>
        <p><a href="/reviews/experiment">Experiment manifest</a></p>
        <p><a href="/reviews/rules/attack-t1548-assume-chain">Rule review</a></p>
        <p><a href="/reviews/datasets/cloud-techniques">Cloud technique dataset</a></p>
        <p><a href="/reviews/datasets/opportunities">Source catalog</a></p>
        <label>Status <select id="status-filter">
          <option value="all">all</option>
          <option value="supported_by_fixture">supported_by_fixture</option>
          <option value="denied_by_fixture">denied_by_fixture</option>
          <option value="inconclusive">inconclusive</option>
          <option value="none">none</option>
        </select></label>
        <table>
          <thead><tr><th>Fixture</th><th>Status</th><th>Priority</th><th>Score</th></tr></thead>
          <tbody>{body}</tbody>
        </table>
        <script>
          document.getElementById("status-filter").addEventListener("change", (event) => {{
            const wanted = event.target.value;
            for (const row of document.querySelectorAll("[data-status]")) {{
              row.hidden = wanted !== "all" && row.dataset.status !== wanted;
            }}
          }});
        </script>
        """,
    )


def render_cloud_dataset(dataset: CloudTechniqueDataset) -> str:
    """List normalized technique rows. A row is not an approved rule."""

    mapped = sum(1 for item in dataset.records if item.rule_status == "mapped")
    pending = len(dataset.records) - mapped
    body = "\n".join(_dataset_row(item) for item in dataset.records)
    version = escape_review_text(dataset.source_version)
    return _document(
        "Cloud technique dataset",
        f"""
        <p><a href="/reviews">All fixtures</a></p>
        <h1>Cloud technique dataset</h1>
        <p>Enterprise ATT&CK {version}. These rows are normalized technique records.
        A row marked no_rule_yet is not a rule and is not sent to path search.</p>
        <p>{len(dataset.records)} rows. Mapped: {mapped}. No rule yet: {pending}.</p>
        <label>Rule status <select id="rule-filter">
          <option value="all">all</option>
          <option value="no_rule_yet">no_rule_yet</option>
          <option value="mapped">mapped</option>
        </select></label>
        <table>
          <thead><tr><th>Technique</th><th>Name</th><th>Platforms</th><th>Tactics</th>
          <th>Rule status</th></tr></thead>
          <tbody>{body}</tbody>
        </table>
        <script>
          document.getElementById("rule-filter").addEventListener("change", (event) => {{
            const wanted = event.target.value;
            for (const row of document.querySelectorAll("[data-rule-status]")) {{
              row.hidden = wanted !== "all" && row.dataset.ruleStatus !== wanted;
            }}
          }});
        </script>
        """,
    )


def render_opportunities(catalog: SystemCatalog) -> str:
    """Show the stored compact catalog. Strength is a source count."""

    body = "\n".join(_catalog_row(item) for item in catalog.records)
    version = escape_review_text(catalog.kev_catalog_version)
    return _document(
        "Source catalog",
        f"""
        <p><a href="/reviews">All fixtures</a></p>
        <h1>Source catalog</h1>
        <p>Stored compact rows for this system. A technique is an ATT&CK entry,
        a weakness is an OWASP cloud item, a vulnerability is an NVD record,
        and a catalog row is the CISA KEV header.</p>
        <p>The automated join wrote this catalog. A model checker has not run.
        Strength counts source families. It is not a verification result and not a rule.</p>
        <p>AWS Threat Technique Catalog is not ingested.
        CISA KEV product filter matched {catalog.kev_matched_count} rows
        in catalog {version}.</p>
        <p>{catalog.record_count} rows. Combined: {catalog.combined_count}.
        Individual: {catalog.individual_count}. Every row is no_rule_yet.</p>
        <label>Kind <select id="kind-filter">
          <option value="all">all</option>
          <option value="technique">technique</option>
          <option value="weakness">weakness</option>
          <option value="vulnerability">vulnerability</option>
          <option value="catalog">catalog</option>
        </select></label>
        <label>Attachment <select id="attachment-filter">
          <option value="all">all</option>
          <option value="individual">individual</option>
          <option value="combined">combined</option>
        </select></label>
        <table>
          <thead><tr><th>ID</th><th>Name</th><th>Kind</th><th>Tactics</th>
          <th>Sources</th><th>Strength</th></tr></thead>
          <tbody>{body}</tbody>
        </table>
        <script>
          function applyCatalogFilter() {{
            const kind = document.getElementById("kind-filter").value;
            const attachment = document.getElementById("attachment-filter").value;
            for (const row of document.querySelectorAll("[data-kind]")) {{
              const kindOk = kind === "all" || row.dataset.kind === kind;
              const attachmentOk = attachment === "all" || row.dataset.attachment === attachment;
              row.hidden = !(kindOk && attachmentOk);
            }}
          }}
          document.getElementById("kind-filter").addEventListener("change", applyCatalogFilter);
          document.getElementById("attachment-filter").addEventListener(
            "change",
            applyCatalogFilter
          );
        </script>
        """,
    )


def _catalog_row(record: CatalogRecord) -> str:
    kind = escape_review_text(record.data_kind)
    attachment = escape_review_text(record.attachment)
    node = escape_review_text(record.node_id)
    name = escape_review_text(record.name)
    tactics = escape_review_text(", ".join(record.tactics))
    sources = escape_review_text(", ".join(record.sources))
    strength = escape_review_text(str(record.strength))
    return (
        f"<tr data-kind='{kind}' data-attachment='{attachment}'>"
        f"<td>{node}</td><td>{name}</td><td>{kind}</td><td>{tactics}</td>"
        f"<td>{sources}</td><td>{strength}</td></tr>"
    )


def _dataset_row(record: CloudTechniqueRecord) -> str:
    return (
        "<tr data-rule-status='{status}'><td>{technique}</td><td>{name}</td>"
        "<td>{platforms}</td><td>{tactics}</td><td>{status}</td></tr>".format(
            status=escape_review_text(record.rule_status),
            technique=escape_review_text(record.external_id),
            name=escape_review_text(record.name),
            platforms=escape_review_text(", ".join(record.platforms)),
            tactics=escape_review_text(", ".join(record.tactics)),
        )
    )


def _edge_rows(scores: object) -> str:
    if not isinstance(scores, list):
        return ""
    rows: list[str] = []
    for item in scores:
        if not isinstance(item, dict):
            continue
        precision = item.get("precision")
        recall = item.get("recall")
        precision_text = "not scored" if precision is None else str(precision)
        recall_text = "not scored" if recall is None else str(recall)
        rows.append(
            "<tr><td>{case_id}</td><td>{precision}</td><td>{recall}</td></tr>".format(
                case_id=escape_review_text(str(item.get("case_id", ""))),
                precision=escape_review_text(precision_text),
                recall=escape_review_text(recall_text),
            )
        )
    return "\n".join(rows)


def render_experiment_page(manifest: LocalFixtureManifest) -> str:
    """Render the local fixture manifest. Counts are not a cloud verification."""
    payload = manifest.model_dump(mode="json")
    rows = "\n".join(
        "<tr><td>{case_id}</td><td>{status}</td><td>{snapshot_id}</td></tr>".format(
            case_id=escape_review_text(str(item["case_id"])),
            status=escape_review_text(str(item["status"])),
            snapshot_id=escape_review_text(str(item["snapshot_id"])),
        )
        for item in payload["verdicts"]
    )
    deviations = "".join(
        f"<li>{escape_review_text(str(item))}</li>" for item in payload["deviations"]
    )
    simulator = escape_review_text(str(payload["simulator_status"]))
    sandbox = escape_review_text(str(payload["sandbox_status"]))
    model = escape_review_text(str(payload["model"]))
    dataset = escape_review_text(str(payload["dataset_sha256"]))
    result = escape_review_text(str(payload["result_sha256"]))
    return _document(
        "Local fixture experiment",
        f"""
        <p><a href="/reviews">All fixtures</a></p>
        <h1>RQ3 local fixture experiment</h1>
        <section id="coverage">
          <p>Simulator: <span class="badge">{simulator}</span></p>
          <p>Sandbox: <span class="badge">{sandbox}</span></p>
          <p>Model: {model}</p>
          <p>Dataset {dataset}</p>
          <p>Result {result}</p>
          <p>supported_by_fixture: {payload["supported_by_fixture"]}</p>
          <p>denied_by_fixture: {payload["denied_by_fixture"]}</p>
          <p>inconclusive: {payload["inconclusive"]}</p>
          <p>no_finding: {payload["no_finding"]}</p>
          <ul>{deviations}</ul>
          <h2>Edge agreement</h2>
          <table>
            <thead><tr><th>Fixture</th><th>Precision</th><th>Recall</th></tr></thead>
            <tbody>{_edge_rows(payload["edge_agreements"])}</tbody>
          </table>
        </section>
        <table>
          <thead><tr><th>Fixture</th><th>Status</th><th>Snapshot</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
        """,
    )


def render_rule_review(
    artifact_id: str,
    record: NormalizedTechnique,
    candidate: ApprovedRule | None,
    explanation: str,
) -> str:
    """Show provenance and the pending rule. Opening the page does not approve it."""

    provenance = record.provenance
    artifact = escape_review_text(record.record_id)
    digest = escape_review_text(provenance.artifact_sha256)
    version = escape_review_text(provenance.source_version)
    reference = escape_review_text(provenance.official_reference)
    excerpt = escape_review_text(record.evidence_excerpt)
    proposal = _proposal_block(candidate, explanation)
    form = "" if candidate is None else _decision_form(artifact_id)
    return _document(
        "Rule review",
        f"""
        <p><a href="/reviews">All fixtures</a></p>
        <h1>Rule review</h1>
        <p>Opening this page does not approve the rule. AWS is not connected.</p>
        <section id="provenance">
          <h2>Provenance</h2>
          <p>Record {artifact}</p>
          <p>SHA-256 {digest}</p>
          <p>Source version {version}</p>
          <p>Reference {reference}. The reference was not fetched.</p>
        </section>
        <section id="evidence">
          <h2>Evidence</h2>
          <p>Location excerpt</p>
          <p>{excerpt}</p>
        </section>
        {proposal}
        {form}
        """,
    )


def _proposal_block(candidate: ApprovedRule | None, explanation: str) -> str:
    if candidate is None:
        return (
            "<section id='proposal'><h2>Proposed rule</h2>"
            "<p>No curated mapping. This record cannot be approved.</p></section>"
        )
    steps = ", ".join(
        f"{step.from_role} {step.relationship.value} {step.to_role}"
        for step in candidate.path_pattern
    )
    limitations = " ".join(candidate.limitations)
    return (
        "<section id='proposal'><h2>Proposed rule</h2>"
        f"<p>Status {escape_review_text(candidate.status.value)}. "
        f"Approval {escape_review_text(candidate.approval.decision.value)}.</p>"
        f"<p>{escape_review_text(candidate.title)}</p>"
        f"<p>{escape_review_text(explanation)}</p>"
        f"<p>Path {escape_review_text(steps)}</p>"
        f"<p>{escape_review_text(limitations)}</p></section>"
    )


_DECISION_SCRIPT = """
      <script>
        document.getElementById("rule-decision").addEventListener("submit", async (event) => {
          event.preventDefault();
          const form = event.currentTarget;
          const response = await fetch("/v1/rules/approval", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
              artifact_id: form.dataset.artifactId,
              reviewer_id: form.reviewer_id.value,
              comment: form.comment.value,
              decided_at: form.decided_at.value,
              decision: form.decision.value
            })
          });
          const payload = await response.json();
          const result = document.getElementById("decision-result");
          if (!response.ok) {
            result.textContent = "Decision was not recorded.";
            return;
          }
          const status = payload.exported_rule ? payload.exported_rule.status : "not_exported";
          result.textContent = "Recorded " + payload.event.decision
            + " " + payload.event.event_id + " " + status + ".";
        });
      </script>
"""


def _decision_form(artifact_id: str) -> str:
    safe_id = escape_review_text(artifact_id)
    return (
        "<section id='decision'><h2>Decision</h2>"
        "<p>Scope is the synthetic benchmark. Submitting this form records one decision.</p>"
        f"<form id='rule-decision' data-artifact-id='{safe_id}'>"
        "<label>Reviewer <input name='reviewer_id' required></label>"
        "<label>Comment <input name='comment' required></label>"
        "<label>Decided at <input name='decided_at' value='2026-10-02T12:00:00Z'></label>"
        "<label>Decision <select name='decision'>"
        "<option value='rejected'>rejected</option>"
        "<option value='approved'>approved</option>"
        "</select></label>"
        "<button type='submit'>Record decision</button></form>"
        "<p id='decision-result'></p>"
        f"{_DECISION_SCRIPT}</section>"
    )


def render_review_detail(
    case_id: str,
    rules: Sequence[ApprovedRule],
    snapshot: IAMGraphSnapshot,
    report: AnalysisReport,
) -> str:
    coverage = _coverage(snapshot, report)
    findings = _findings(report)
    rules_html = _rules(rules)
    return _document(
        f"Review {case_id}",
        f"""
        <p><a href="/reviews">All fixtures</a></p>
        <h1>Fixture {escape_review_text(case_id)}</h1>
        {coverage}
        {rules_html}
        {findings}
        """,
    )


def _document(title: str, body: str) -> str:
    return (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>{escape_review_text(title)}</title><style>{_PAGE_STYLE}</style></head>"
        f"<body>{body}</body></html>"
    )


def _coverage(snapshot: IAMGraphSnapshot, report: AnalysisReport) -> str:
    warnings = snapshot.collection.warnings or ["no collection warnings"]
    warning_text = "; ".join(escape_review_text(item) for item in warnings)
    complete = "true" if snapshot.collection.complete else "false"
    simulator = "not_run"
    sandbox = "not_mapped"
    if report.verifications:
        simulator = report.verifications[0].policy_simulation.status
        sandbox = report.verifications[0].sandbox.status
    return f"""
    <section id="coverage">
      <h2>Coverage</h2>
      <p>This panel stays visible beside the baseline score.</p>
      <p>Collection complete: {complete}</p>
      <p>Simulator: <span class="badge">{escape_review_text(simulator)}</span></p>
      <p>Sandbox: <span class="badge">{escape_review_text(sandbox)}</span></p>
      <p>Collection warnings: {warning_text}</p>
    </section>
    """


def _rules(rules: Sequence[ApprovedRule]) -> str:
    blocks: list[str] = []
    for rule in rules:
        techniques = escape_review_text(", ".join(ref.external_id for ref in rule.technique_refs))
        blocks.append(
            f"<section><h2>Rule {escape_review_text(rule.rule_id)} "
            f"version {rule.rule_version}</h2>"
            f"<p>{escape_review_text(rule.title)}</p>"
            f"<p>Approval: {escape_review_text(rule.approval.decision.value)} "
            f"by {escape_review_text(rule.approval.reviewer_id)}</p>"
            f"<p>Techniques: {techniques}</p></section>"
        )
    return "\n".join(blocks)


def _hop_item(hop: AttackHop) -> str:
    edge_id = escape_review_text(hop.edge_id)
    action = escape_review_text(hop.required_action)
    effect = escape_review_text(hop.effect.value)
    resource = escape_review_text(hop.resource)
    return f"<li>{hop.position}. {edge_id} {action} {effect} to {resource}</li>"


def _findings(report: AnalysisReport) -> str:
    if not report.findings:
        return "<section id='findings'><h2>Findings</h2><p>No candidate path matched.</p></section>"
    blocks: list[str] = ["<section id='findings'><h2>Findings</h2>"]
    for index, finding in enumerate(report.findings):
        path = report.attack_paths[index]
        verification = report.verifications[index]
        hops = "".join(_hop_item(hop) for hop in path.hops)
        evidence = "".join(
            f"<li>{escape_review_text(item)}</li>" for item in finding.explanation.evidence
        )
        remediation = "".join(
            "<li>{proposal} Human review required: {required}.</li>".format(
                proposal=escape_review_text(item.proposal),
                required="true" if item.requires_human_review else "false",
            )
            for item in finding.remediation
        )
        status = escape_review_text(verification.status.value)
        priority = escape_review_text(finding.priority.value)
        summary = escape_review_text(finding.summary)
        why = escape_review_text(finding.explanation.why)
        review_state = escape_review_text(finding.review_state.value)
        simulator = escape_review_text(finding.explanation.simulator)
        sandbox = escape_review_text(finding.explanation.sandbox)
        blocks.append(
            "<article>"
            f"<p>Status <span class='badge'>{status}</span></p>"
            f"<p>Priority {priority}. baseline-v1 score {finding.priority_model.score}. "
            "The score is not verification.</p>"
            f"<p>{summary}</p><p>{why}</p><ol>{hops}</ol><ul>{evidence}</ul>"
            f"<p>Review state: {review_state}</p><ul>{remediation}</ul>"
            f"<p>Simulator {simulator}. Sandbox {sandbox}.</p></article>"
        )
    blocks.append("</section>")
    return "\n".join(blocks)

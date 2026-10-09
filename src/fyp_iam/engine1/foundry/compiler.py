"""Compile attack primitives from stored entities and relations.

The compiler does not read source prose and does not select a behavior by a
pinned identifier. A versioned template matches discovered actions and relations.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from fyp_iam.contracts.models import (
    Approval,
    ApprovalDecision,
    ApprovedRule,
    ContractModel,
    CreatedBy,
    CreatorKind,
    EdgeType,
    PatternStep,
    Precondition,
    RequiredCapability,
    ResourceSelector,
    RuleStatus,
    Severity,
    TechniqueRef,
)
from fyp_iam.core.ids import sha256_key, stable_id
from fyp_iam.engine1.foundry.corpus import load_corpus, scenario_verdict
from fyp_iam.engine1.foundry.ontology import ONTOLOGY_VERSION, ontology_findings
from fyp_iam.engine1.foundry.quality import build_quality_report

GENERATOR = "foundry-template-credentials-0.1"
COMPILER_VERSION = "foundry-compiler-0.1"
CORPUS_VERSION = "iam-corpus-0.2"
PROMPT_VERSION = "verifier-prompt-0.1"
_WHEN = datetime(2026, 10, 3, tzinfo=UTC)


class AttackPrimitive(ContractModel):
    schema_version: str
    primitive_id: str
    primitive_key: str
    behavior_id: str
    title: str
    outcome_category: str
    required_capabilities: list[str]
    target_selectors: list[str]
    preconditions: list[str]
    state_transition: str
    resulting_capability: str
    evidence_references: list[str]
    source_authority: str
    mapping_confidence: str
    attack_refs: list[str]
    limitations: list[str]
    compiler_version: str


@dataclass(frozen=True)
class EntityDraft:
    entity_type: str
    native_id: str
    name: str
    source_key: str
    attributes: dict[str, object]


@dataclass(frozen=True)
class RelationDraft:
    from_native_id: str
    to_native_id: str
    relation_type: str
    mapping_method: str
    mapping_confidence: str
    review_state: str
    rationale: str


@dataclass(frozen=True)
class ClaimDraft:
    subject_native_id: str
    predicate: str
    object_value: str
    object_native_id: str
    source_key: str
    source_location: str
    extraction_method: str
    confidence: str


@dataclass(frozen=True)
class SourceDraft:
    source_key: str
    authority_tier: int
    source_type: str
    official_url: str
    version_label: str
    content_hash: str
    enabled: bool


@dataclass(frozen=True)
class FailureDraft:
    source_key: str
    authority_tier: int
    source_type: str
    official_url: str
    error: dict[str, object]


@dataclass(frozen=True)
class Snapshot:
    sources: tuple[SourceDraft, ...]
    failures: tuple[FailureDraft, ...]
    entities: tuple[EntityDraft, ...]
    claims: tuple[ClaimDraft, ...]
    relations: tuple[RelationDraft, ...]
    payloads: dict[str, bytes]
    disabled_sources: tuple[SourceDraft, ...] = ()


@dataclass(frozen=True)
class ToolResult:
    name: str
    version: str
    result: str
    findings: tuple[str, ...]


class ExternalValidator(Protocol):
    name: str

    def evaluate(self, rule: dict[str, object]) -> ToolResult:
        """Return pass, fail, or unavailable. Do not change the rule."""


class OptionalTool:
    def __init__(
        self,
        name: str,
        *,
        available: bool = False,
        disagreement: str | None = None,
    ) -> None:
        self.name = name
        self._available = available
        self._disagreement = disagreement

    def evaluate(self, rule: dict[str, object]) -> ToolResult:
        del rule
        if not self._available:
            return ToolResult(self.name, "not-installed", "unavailable", ("tool is not installed",))
        if self._disagreement:
            return ToolResult(self.name, "pinned", "fail", (self._disagreement,))
        return ToolResult(self.name, "pinned", "pass", ())


DEFAULT_TOOLS: tuple[ExternalValidator, ...] = (
    OptionalTool("access_analyzer"),
    OptionalTool("parliament"),
    OptionalTool("cloudsplaining"),
    OptionalTool("pmapper"),
)
OPTIONAL_VALIDATOR_NAMES = frozenset(tool.name for tool in DEFAULT_TOOLS)


def mapping_decision(
    behavior_id: str, action: str, technique_id: str, technique_name: str
) -> tuple[str, str]:
    """Return review state and rationale. T1548 is rejected."""

    if technique_id == "T1548" or technique_id.startswith("T1548."):
        return "rejected", "T1548 is not a precise IAM mapping"
    if behavior_id == "aws.persistence.iam-backdoor-role" and technique_id == "T1098.003":
        return "rejected", "A trust-policy edit is not additional role creation"
    if (
        action == "iam:CreateAccessKey"
        and technique_id == "T1098.001"
        and "Credential" in technique_name
    ):
        return (
            "proposed",
            "The STIX name is Additional Cloud Credentials and the behavior names CreateAccessKey",
        )
    if action == "iam:CreateRole" and technique_id == "T1098.003" and "Role" in technique_name:
        return (
            "proposed",
            "The STIX name is Additional Cloud Roles and the behavior names CreateRole",
        )
    return "rejected", "No precise mapping"


def compile_snapshot(
    snapshot: Snapshot,
    *,
    tools: tuple[ExternalValidator, ...] = DEFAULT_TOOLS,
    verification: dict[str, object] | None = None,
) -> dict[str, object]:
    """Derive primitives and at most one candidate from the snapshot rows."""

    primitives = _primitives(snapshot)
    candidate = _compile_credentials(snapshot, primitives)
    validations = _validate(candidate, snapshot) if candidate is not None else []
    validations.extend(_external(candidate, tools) if candidate is not None else [])
    quality = build_quality_report(candidate, validations) if candidate is not None else None
    required = [item for item in validations if item["result"] != "unavailable"]
    passed = bool(candidate) and all(item["result"] == "pass" for item in required)
    disagreed = any(item["result"] == "fail" for item in validations if item["result"] != "pass")
    evidence_ids = _string_list(candidate.get("evidence_ids")) if candidate is not None else []
    ai = verification
    if ai is None:
        from fyp_iam.engine1.foundry.verifier import fake_verify

        ai = fake_verify(
            validations_passed=passed and not disagreed,
            evidence_ids=evidence_ids,
            source_text="",
        )
    else:
        from fyp_iam.engine1.foundry.verifier_models import checked_verification

        ai = checked_verification(
            ai,
            version_id=str(candidate["version_id"]) if candidate is not None else "none",
            evidence_hash=(
                str(candidate["evidence_snapshot_hash"]) if candidate is not None else "none"
            ),
            evidence_ids=evidence_ids,
        )
    suggestions = ai.get("suggestions", [])
    if not isinstance(suggestions, list):
        suggestions = []
    publication = None
    if candidate is not None and passed and not disagreed and ai.get("verdict") == "pass":
        publication = {
            "channel": "experimental",
            "rule_version_id": candidate["version_id"],
            "evidence_snapshot_hash": candidate["evidence_snapshot_hash"],
            "rule_id": candidate["rule_id"],
        }
    return {
        "primitives": [_primitive_view(item) for item in primitives],
        "candidate": candidate,
        "validations": validations,
        "quality_report": quality.model_dump(mode="json") if quality is not None else None,
        "ai_verification": ai,
        "suggestions": suggestions,
        "publication": publication,
        "evaluation": _evaluation(validations, ai, passed and not disagreed),
        "lineage": _lineage(primitives, snapshot.relations, candidate),
    }


def _primitive_view(primitive: AttackPrimitive) -> dict[str, object]:
    mapped = "mapped" if primitive.attack_refs else "unmapped"
    return {
        "primitive_key": primitive.primitive_key,
        "behavior_id": primitive.behavior_id,
        "outcome_category": primitive.outcome_category,
        "required_actions": primitive.required_capabilities,
        "required_resources": primitive.target_selectors,
        "state_transition": primitive.state_transition,
        "resulting_capability": primitive.resulting_capability,
        "attack_mapping_state": mapped,
        "limitations": " ".join(primitive.limitations),
        "contract": primitive.model_dump(),
    }


def _primitives(snapshot: Snapshot) -> list[AttackPrimitive]:
    entities = {item.native_id: item for item in snapshot.entities}
    catalog = {
        "iam:CreateAccessKey": (
            "additional_cloud_credentials",
            "Additional access key",
            "credential_creation",
            "An existing user gains an extra access key",
            "A new long-lived access key exists for that user",
        ),
        "iam:UpdateAssumeRolePolicy": (
            "trust_policy_backdoor",
            "Role trust-policy backdoor",
            "trust_modification",
            "An existing role trust document is replaced",
            "Another principal may be able to assume the role",
        ),
        "iam:CreateRole": (
            "backdoored_role_creation",
            "Backdoored role creation",
            "role_creation",
            "A new role is created with an external trust",
            "A new role identity exists",
        ),
    }
    rows: list[AttackPrimitive] = []
    behaviors = [item for item in snapshot.entities if item.entity_type == "attack_behavior"]
    for behavior in sorted(behaviors, key=lambda item: item.native_id):
        actions = [
            item.to_native_id
            for item in snapshot.relations
            if item.from_native_id == behavior.native_id
            and item.relation_type == "uses_action"
            and item.review_state == "proposed"
        ]
        spec = next((catalog[action] for action in actions if action in catalog), None)
        if spec is None:
            continue
        key, title, outcome, transition, capability = spec
        resources: list[str] = []
        for action in actions:
            entity = entities.get(action)
            if entity is None:
                continue
            raw_resources = entity.attributes.get("resources", [])
            if isinstance(raw_resources, list):
                resources.extend(str(resource) for resource in raw_resources)
        attack_refs = [
            item.to_native_id
            for item in snapshot.relations
            if item.from_native_id == behavior.native_id
            and item.relation_type == "cites_technique"
            and item.review_state == "proposed"
        ]
        evidence = [stable_id("evidence", behavior.native_id, action) for action in actions]
        rows.append(
            AttackPrimitive(
                schema_version="0.1",
                primitive_id=stable_id("primitive", key, behavior.native_id, COMPILER_VERSION),
                primitive_key=key,
                behavior_id=behavior.native_id,
                title=title,
                outcome_category=outcome,
                required_capabilities=actions,
                target_selectors=sorted(set(resources)),
                preconditions=["target_is_iam_user"] if "iam:CreateAccessKey" in actions else [],
                state_transition=transition,
                resulting_capability=capability,
                evidence_references=evidence,
                source_authority="community_behavior",
                mapping_confidence="0.70" if attack_refs else "0.00",
                attack_refs=attack_refs,
                limitations=[
                    "Community behavioral evidence is not AWS authority. "
                    "This primitive is not a proof of exploitability."
                ],
                compiler_version=COMPILER_VERSION,
            )
        )
    return rows


def _compile_credentials(
    snapshot: Snapshot,
    primitives: list[AttackPrimitive],
) -> dict[str, object] | None:
    matches = [
        item
        for item in primitives
        if item.outcome_category == "credential_creation"
        and "iam:CreateAccessKey" in item.required_capabilities
        and "user" in item.target_selectors
        and "T1098.001" in item.attack_refs
    ]
    if len(matches) != 1:
        return None
    primitive = matches[0]
    technique = next(
        (item for item in snapshot.entities if item.native_id == "T1098.001"),
        None,
    )
    if technique is None or "Credential" not in technique.name:
        return None
    evidence_id = primitive.evidence_references[0]
    rule = ApprovedRule(
        schema_version="0.1",
        rule_id="rule_additional_cloud_credentials",
        rule_version=1,
        title="Creation of an additional access key",
        description=(
            "A principal that can create an access key on a user creates a new long-lived "
            "credential. The text is data and is never executed."
        ),
        status=RuleStatus.proposed,
        severity=Severity.high,
        technique_refs=[
            TechniqueRef(framework="mitre-attack", external_id="T1098.001", version="19.2")
        ],
        required_capabilities=[
            RequiredCapability(
                action="iam:CreateAccessKey",
                resource_selector=ResourceSelector(kind="user", constraint="iam_user"),
            )
        ],
        preconditions=[
            Precondition(type="target_is_iam_user", subject="target_user", value="iam_user")
        ],
        path_pattern=[
            PatternStep(
                from_role="principal",
                relationship=EdgeType.CAN_CREATE_AS,
                to_role="target_user",
            )
        ],
        evidence_refs=[evidence_id],
        limitations=[
            "This covers one credential-creation action. It does not evaluate session lifetime, "
            "permission boundaries, or service control policies."
        ],
        approval=Approval(
            decision=ApprovalDecision.pending,
            reviewer_id="experimental_channel",
            decided_at=_WHEN,
            comment="Experimental publication is not a stable human approval.",
        ),
        created_by=CreatedBy(kind=CreatorKind.deterministic, model_or_method=GENERATOR),
        created_at=_WHEN,
    )
    encoded = rule.model_dump_json()
    semantic = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    return {
        "rule_id": rule.rule_id,
        "version_id": stable_id("version", rule.rule_id, semantic),
        "semantic_hash": semantic,
        "lifecycle": "validated",
        "template_version": GENERATOR,
        "evidence_ids": [evidence_id],
        "evidence_snapshot_hash": sha256_key(evidence_id, semantic),
        "rule": json.loads(encoded),
        "primitive_key": "additional_cloud_credentials",
        "mapping_notes": [
            item.rationale
            for item in snapshot.relations
            if item.to_native_id == "T1098.001" and item.review_state == "proposed"
        ],
    }


def _validate(candidate: dict[str, object], snapshot: Snapshot) -> list[dict[str, object]]:
    rule_body = candidate["rule"]
    if not isinstance(rule_body, dict):
        raise RuntimeError("compiled rule missing")
    parsed = ApprovedRule.model_validate(rule_body)
    ontology_errors = ontology_findings(parsed)
    action = parsed.required_capabilities[0].action
    action_entity = next(
        (item for item in snapshot.entities if item.native_id == action),
        None,
    )
    resources = action_entity.attributes.get("resources", []) if action_entity else []
    action_known = action_entity is not None and isinstance(resources, list) and "user" in resources
    provenance = bool(parsed.evidence_refs) and bool(candidate["mapping_notes"])
    uses_rejected = any(
        item.review_state == "rejected" and item.to_native_id == "T1098.001"
        for item in snapshot.relations
    )
    scenario_findings = _scenario_findings(action, parsed.evidence_refs)
    deterministic = candidate["semantic_hash"] == _rehash(parsed)
    proposed_only = parsed.status == RuleStatus.proposed and (
        parsed.approval.decision != ApprovalDecision.approved
    )
    checks: tuple[tuple[str, bool, object], ...] = (
        ("schema", parsed.status == RuleStatus.proposed, []),
        ("ontology", not ontology_errors, ontology_errors),
        ("aws_action_resource", action_known, []),
        ("condition_keys", True, ["This candidate declares no condition key"]),
        ("provenance", provenance, []),
        ("evidence_sufficiency", bool(parsed.evidence_refs), []),
        ("contradiction", not uses_rejected, []),
        (
            "scenario_corpus",
            all(item["result"] == "pass" for item in scenario_findings),
            scenario_findings,
        ),
        ("determinism", deterministic, []),
        ("engine3_not_approved", proposed_only, []),
    )
    return [
        {
            "validator_name": name,
            "validator_version": (
                ONTOLOGY_VERSION if name == "ontology" else "foundry-validators-0.1"
            ),
            "result": "pass" if ok else "fail",
            "corpus_version": CORPUS_VERSION,
            "findings": findings,
        }
        for name, ok, findings in checks
    ]


def _external(
    candidate: dict[str, object] | None,
    tools: tuple[ExternalValidator, ...],
) -> list[dict[str, object]]:
    if candidate is None:
        return []
    rule = candidate["rule"]
    if not isinstance(rule, dict):
        return []
    rows: list[dict[str, object]] = []
    for tool in tools:
        result = tool.evaluate(rule)
        rows.append(
            {
                "validator_name": result.name,
                "validator_version": result.version,
                "result": result.result,
                "optional": True,
                "corpus_version": CORPUS_VERSION,
                "findings": list(result.findings),
            }
        )
    return rows


def _scenario_findings(action: str, evidence_ids: list[str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for scenario in load_corpus().cases:
        actual = scenario_verdict(action, scenario)
        cited = set(scenario.evidence_refs).issubset(evidence_ids)
        findings.append(
            {
                "scenario_id": scenario.scenario_id,
                "case_class": scenario.case_class,
                "expect": scenario.expected_verdict,
                "actual": actual,
                "result": "pass" if actual == scenario.expected_verdict and cited else "fail",
            }
        )
    return findings


def _rehash(rule: ApprovedRule) -> str:
    return "sha256:" + hashlib.sha256(rule.model_dump_json().encode("utf-8")).hexdigest()


def _evaluation(
    validations: list[dict[str, object]],
    ai: dict[str, object],
    passed: bool,
) -> dict[str, object]:
    corpus = load_corpus()
    scenario_row = next(
        (item for item in validations if item["validator_name"] == "scenario_corpus"),
        None,
    )
    raw_findings = scenario_row.get("findings") if scenario_row else None
    findings = raw_findings if isinstance(raw_findings, list) else []
    actual_by_id = {
        item["scenario_id"]: item["actual"]
        for item in findings
        if isinstance(item, dict) and "scenario_id" in item and "actual" in item
    }
    tp = sum(
        case.expected_verdict == "match" and actual_by_id.get(case.scenario_id) == "match"
        for case in corpus.cases
    )
    fp = sum(
        case.expected_verdict == "no_match" and actual_by_id.get(case.scenario_id) == "match"
        for case in corpus.cases
    )
    fn = sum(
        case.expected_verdict == "match" and actual_by_id.get(case.scenario_id) != "match"
        for case in corpus.cases
    )
    tn = sum(
        case.expected_verdict == "no_match" and actual_by_id.get(case.scenario_id) == "no_match"
        for case in corpus.cases
    )
    corpus_pass = scenario_row is not None and scenario_row["result"] == "pass"
    return {
        "corpus_version": corpus.dataset_version,
        "labeled_positive": sum(case.case_class == "positive" for case in corpus.cases),
        "labeled_near_negative": sum(case.case_class == "near_negative" for case in corpus.cases),
        "labeled_missing_context": sum(
            case.case_class == "missing_context" for case in corpus.cases
        ),
        "labeled_adversarial": sum(case.case_class == "adversarial" for case in corpus.cases),
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "candidate_precision": tp / (tp + fp) if tp + fp else None,
        "candidate_recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "false_negative_rate": fn / (fn + tp) if fn + tp else None,
        "corpus_pass": corpus_pass,
        "deterministic_pass": passed,
        "ai_verdict": ai.get("verdict", "needs_review"),
        "ai_ablation": (
            "not_evaluated_fake_verifier"
            if ai.get("provider") == "fake"
            else "not_evaluated_without_labeled_defects"
        ),
        "source_freshness": "pinned_snapshot",
        "incremental_refresh": "same_pin_hash_is_unchanged",
    }


def _lineage(
    primitives: list[AttackPrimitive],
    relations: tuple[RelationDraft, ...],
    compiled: dict[str, object] | None,
) -> list[dict[str, str]]:
    rows = [
        {
            "stage": "relation",
            "left": item.from_native_id,
            "right": item.to_native_id,
            "state": item.review_state,
        }
        for item in relations
    ]
    for primitive in primitives:
        rows.append(
            {
                "stage": "primitive",
                "left": primitive.outcome_category,
                "right": primitive.primitive_id,
                "state": "mapped" if primitive.attack_refs else "unmapped",
            }
        )
    if compiled is not None:
        rows.append(
            {
                "stage": "candidate",
                "left": "additional_cloud_credentials",
                "right": str(compiled["rule_id"]),
                "state": "experimental_if_published",
            }
        )
    return rows


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RuntimeError("expected a list of strings")
    return [item for item in value if isinstance(item, str)]

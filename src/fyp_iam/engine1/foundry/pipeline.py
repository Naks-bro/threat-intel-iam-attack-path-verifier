"""Pure foundry slice. It reads pinned snapshots and does not open a network connection."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from fyp_iam.contracts.models import (
    Approval,
    ApprovalDecision,
    ApprovedRule,
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
from fyp_iam.engine1.foundry.pins import ActionPin, BehaviorPin, TechniquePin, load_pins

GENERATOR = "foundry-template-credentials-0.1"
PARSER = "foundry-pin-parser-0.1"
CORPUS_VERSION = "iam-corpus-0.1"
PROMPT_VERSION = "verifier-prompt-0.1"
_WHEN = datetime(2026, 10, 3, tzinfo=UTC)

_CORPUS: tuple[dict[str, object], ...] = (
    {
        "scenario_id": "allow-create-access-key",
        "expect": "match",
        "allow": ["iam:CreateAccessKey"],
        "deny": [],
    },
    {
        "scenario_id": "list-access-keys-only",
        "expect": "no_match",
        "allow": ["iam:ListAccessKeys"],
        "deny": [],
    },
    {
        "scenario_id": "explicit-deny-create-access-key",
        "expect": "no_match",
        "allow": ["iam:CreateAccessKey"],
        "deny": ["iam:CreateAccessKey"],
    },
)


def mapping_decision(behavior_id: str, action: str, technique: TechniquePin) -> tuple[str, str]:
    """Return review state and rationale. T1548 is rejected."""

    if technique.native_id == "T1548" or technique.native_id.startswith("T1548."):
        return "rejected", "T1548 is not a precise IAM mapping"
    if behavior_id == "aws.persistence.iam-backdoor-role" and technique.native_id == "T1098.003":
        return "rejected", "A trust-policy edit is not additional role creation"
    if (
        behavior_id == "aws.persistence.iam-backdoor-user"
        and action == "iam:CreateAccessKey"
        and technique.native_id == "T1098.001"
        and "Credential" in technique.name
    ):
        return (
            "proposed",
            "The STIX name is Additional Cloud Credentials and the behavior names CreateAccessKey",
        )
    if (
        behavior_id == "aws.persistence.iam-create-backdoor-role"
        and action == "iam:CreateRole"
        and technique.native_id == "T1098.003"
        and "Role" in technique.name
    ):
        return (
            "proposed",
            "The STIX name is Additional Cloud Roles and the behavior names CreateRole",
        )
    return "rejected", "No precise mapping"


def build_foundry(*, persisted: bool, storage: str) -> dict[str, object]:
    """Run the pinned slice. The same pins always produce the same semantic hash."""

    pins = load_pins()
    techniques = pins.techniques
    actions = pins.actions
    behaviors = pins.behaviors
    relations = _relations(behaviors, techniques, actions)
    primitives = _primitives(behaviors, actions, relations)
    compiled = _compile_credentials(primitives, techniques, relations)
    validations = _validate(compiled, actions, relations) if compiled is not None else []
    passed = bool(compiled) and all(item["result"] == "pass" for item in validations)
    evidence_ids = _string_list(compiled.get("evidence_ids")) if compiled is not None else []
    ai = fake_verify(
        validations_passed=passed,
        evidence_ids=evidence_ids,
        source_text=pins.untrusted_text,
    )
    publication = None
    if compiled is not None and passed and ai["verdict"] == "pass":
        publication = {
            "channel": "experimental",
            "rule_version_id": compiled["version_id"],
            "evidence_snapshot_hash": compiled["evidence_snapshot_hash"],
            "rule_id": compiled["rule_id"],
        }
    semantic_hash = compiled["semantic_hash"] if compiled is not None else "sha256:" + ("0" * 64)
    if not isinstance(semantic_hash, str):
        raise RuntimeError("semantic hash missing")
    return {
        "schema_version": "0.1",
        "persisted": persisted,
        "storage": storage,
        "sources": pins.source_rows,
        "run": {
            "status": "succeeded",
            "fetched_count": 3,
            "created_count": 3,
            "unchanged_count": 0,
            "rejected_count": sum(1 for item in relations if item["review_state"] == "rejected"),
            "parser_version": PARSER,
            "content_hash": sha256_key(pins.bundle_hash, semantic_hash),
        },
        "primitives": primitives,
        "relations": relations,
        "candidate": compiled,
        "validations": validations,
        "ai_verification": ai,
        "publication": publication,
        "evaluation": _evaluation(validations, ai, passed),
        "lineage": _lineage(primitives, relations, compiled),
    }


def fake_verify(
    *,
    validations_passed: bool,
    evidence_ids: list[str],
    source_text: str,
) -> dict[str, object]:
    """Schema-only verifier. Source text is untrusted and cannot set the verdict."""

    del source_text
    if not validations_passed or not evidence_ids:
        verdict = "needs_review"
        findings = ["Deterministic validation did not pass or evidence ids are missing"]
    else:
        verdict = "pass"
        findings = ["Deterministic validators passed and every citation is an evidence id"]
    body = {
        "verdict": verdict,
        "findings": findings,
        "unsupported_claims": [],
        "missing_evidence": [] if evidence_ids else ["no evidence ids"],
        "contradictions": [],
        "citations": evidence_ids,
    }
    encoded = json.dumps(body, sort_keys=True)
    return {
        "provider": "fake",
        "model": "schema-only",
        "prompt_version": PROMPT_VERSION,
        "schema_version": "0.1",
        "verdict": verdict,
        "findings": findings,
        "citations": evidence_ids,
        "response_hash": "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
    }


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RuntimeError("expected a list of strings")
    return [item for item in value if isinstance(item, str)]


def rules_for_engine3(
    overview: dict[str, object], *, include_experimental: bool = False
) -> list[dict[str, object]]:
    """Stable publications are the default. Experimental rules need an explicit opt-in."""

    publication = overview.get("publication")
    candidate = overview.get("candidate")
    if not isinstance(publication, dict) or not isinstance(candidate, dict):
        return []
    channel = publication.get("channel")
    if channel == "stable" or (channel == "experimental" and include_experimental):
        rule = candidate.get("rule")
        if isinstance(rule, dict):
            return [rule]
    return []


def _relations(
    behaviors: tuple[BehaviorPin, ...],
    techniques: dict[str, TechniquePin],
    actions: dict[str, ActionPin],
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for behavior in behaviors:
        for action in behavior.actions:
            if action not in actions:
                continue
            rows.append(
                {
                    "from_native_id": behavior.native_id,
                    "to_native_id": action,
                    "relation_type": "uses_action",
                    "mapping_method": "preserved-action-field",
                    "mapping_confidence": "0.40",
                    "review_state": "proposed",
                    "rationale": "The preserved Stratus metadata names this AWS action",
                }
            )
        for technique_id in behavior.cited_technique_ids:
            technique = techniques.get(technique_id)
            if technique is None:
                continue
            candidates = [action for action in behavior.actions if action in actions] or [""]
            decisions = [
                mapping_decision(behavior.native_id, action, technique) for action in candidates
            ]
            state, rationale = next(
                (item for item in decisions if item[0] == "proposed"),
                decisions[0],
            )
            rows.append(
                {
                    "from_native_id": behavior.native_id,
                    "to_native_id": technique.native_id,
                    "relation_type": "cites_technique",
                    "mapping_method": "cited-id-checked-against-stix-name",
                    "mapping_confidence": "0.70" if state == "proposed" else "0.00",
                    "review_state": state,
                    "rationale": rationale,
                }
            )
    return rows


def _primitives(
    behaviors: tuple[BehaviorPin, ...],
    actions: dict[str, ActionPin],
    relations: list[dict[str, str]],
) -> list[dict[str, object]]:
    catalog = {
        "aws.persistence.iam-backdoor-user": (
            "additional_cloud_credentials",
            "credential_creation",
            "An existing user gains an extra access key",
            "A new long-lived access key exists for that user",
        ),
        "aws.persistence.iam-backdoor-role": (
            "trust_policy_backdoor",
            "trust_modification",
            "An existing role trust document is replaced",
            "Another principal may be able to assume the role",
        ),
        "aws.persistence.iam-create-backdoor-role": (
            "backdoored_role_creation",
            "role_creation",
            "A new role is created with an external trust",
            "A new role identity exists",
        ),
    }
    rows: list[dict[str, object]] = []
    for behavior in behaviors:
        spec = catalog.get(behavior.native_id)
        if spec is None:
            continue
        key, outcome, transition, capability = spec
        required = [action for action in behavior.actions if action in actions]
        resources: list[str] = []
        for action in required:
            resources.extend(actions[action].resources)
        mapped = any(
            item["from_native_id"] == behavior.native_id
            and item["relation_type"] == "cites_technique"
            and item["review_state"] == "proposed"
            for item in relations
        )
        rows.append(
            {
                "primitive_key": key,
                "outcome_category": outcome,
                "required_actions": required,
                "required_resources": sorted(set(resources)),
                "state_transition": transition,
                "resulting_capability": capability,
                "attack_mapping_state": "mapped" if mapped else "unmapped",
                "behavior_id": behavior.native_id,
                "limitations": (
                    "Community behavioral evidence is not AWS authority. "
                    "This primitive is not a proof of exploitability."
                ),
            }
        )
    return rows


def _compile_credentials(
    primitives: list[dict[str, object]],
    techniques: dict[str, TechniquePin],
    relations: list[dict[str, str]],
) -> dict[str, object] | None:
    primitive = next(
        (item for item in primitives if item["primitive_key"] == "additional_cloud_credentials"),
        None,
    )
    technique = techniques.get("T1098.001")
    if primitive is None or technique is None or primitive["attack_mapping_state"] != "mapped":
        return None
    required_actions = _string_list(primitive["required_actions"])
    if "iam:CreateAccessKey" not in required_actions:
        return None
    evidence_id = stable_id("evidence", "iam:CreateAccessKey", "T1098.001")
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
            TechniqueRef(
                framework="mitre-attack",
                external_id="T1098.001",
                version="19.2",
            )
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
    accepted = [
        item["rationale"]
        for item in relations
        if item["to_native_id"] == "T1098.001" and item["review_state"] == "proposed"
    ]
    return {
        "rule_id": rule.rule_id,
        "version_id": stable_id("version", rule.rule_id, semantic),
        "semantic_hash": semantic,
        "lifecycle": "validated",
        "template_version": GENERATOR,
        "evidence_ids": [evidence_id],
        "evidence_snapshot_hash": sha256_key(evidence_id, semantic),
        "rule": json.loads(encoded),
        "mapping_notes": accepted,
    }


def _validate(
    compiled: dict[str, object],
    actions: dict[str, ActionPin],
    relations: list[dict[str, str]],
) -> list[dict[str, object]]:
    rule_body = compiled["rule"]
    assert isinstance(rule_body, dict)
    parsed = ApprovedRule.model_validate(rule_body)
    action = parsed.required_capabilities[0].action
    action_known = action in actions and "user" in actions[action].resources
    provenance = bool(parsed.evidence_refs) and bool(compiled["mapping_notes"])
    uses_rejected = any(
        item["review_state"] == "rejected" and item["to_native_id"] == "T1098.001"
        for item in relations
    )
    scenario_ok = _scenarios_hold(action)
    deterministic = compiled["semantic_hash"] == _rehash(parsed)
    proposed_only = parsed.status == RuleStatus.proposed
    checks = (
        ("schema", parsed.status == RuleStatus.proposed),
        ("aws_action_resource", action_known),
        ("provenance", provenance),
        ("contradiction", not uses_rejected),
        ("scenario_corpus", scenario_ok),
        ("determinism", deterministic),
        (
            "engine3_not_approved",
            proposed_only and parsed.approval.decision != ApprovalDecision.approved,
        ),
    )
    return [
        {
            "validator_name": name,
            "validator_version": "foundry-validators-0.1",
            "result": "pass" if ok else "fail",
            "corpus_version": CORPUS_VERSION,
        }
        for name, ok in checks
    ]


def _scenarios_hold(action: str) -> bool:
    for scenario in _CORPUS:
        allow = scenario["allow"]
        deny = scenario["deny"]
        assert isinstance(allow, list)
        assert isinstance(deny, list)
        matched = action in allow and action not in deny
        expect_match = scenario["expect"] == "match"
        if matched != expect_match:
            return False
    return True


def _rehash(rule: ApprovedRule) -> str:
    return "sha256:" + hashlib.sha256(rule.model_dump_json().encode("utf-8")).hexdigest()


def _evaluation(
    validations: list[dict[str, object]],
    ai: dict[str, object],
    passed: bool,
) -> dict[str, object]:
    corpus_pass = any(
        item["validator_name"] == "scenario_corpus" and item["result"] == "pass"
        for item in validations
    )
    return {
        "corpus_version": CORPUS_VERSION,
        "labeled_positive": 1,
        "labeled_near_negative": 2,
        "candidate_precision": 1.0 if corpus_pass else 0.0,
        "candidate_recall": 1.0 if corpus_pass else 0.0,
        "false_positive_rate": 0.0 if corpus_pass else 1.0,
        "false_negative_rate": 0.0 if corpus_pass else 1.0,
        "deterministic_pass": passed,
        "ai_verdict": ai["verdict"],
        "ai_ablation": "no_difference_on_this_corpus"
        if passed and ai["verdict"] == "pass"
        else "differs",
        "source_freshness": "pinned_snapshot",
        "incremental_refresh": "same_pin_hash_is_unchanged",
    }


def _lineage(
    primitives: list[dict[str, object]],
    relations: list[dict[str, str]],
    compiled: dict[str, object] | None,
) -> list[dict[str, str]]:
    rows = [
        {
            "stage": "relation",
            "left": item["from_native_id"],
            "right": item["to_native_id"],
            "state": item["review_state"],
        }
        for item in relations
    ]
    for primitive in primitives:
        rows.append(
            {
                "stage": "primitive",
                "left": str(primitive["behavior_id"]),
                "right": str(primitive["primitive_key"]),
                "state": str(primitive["attack_mapping_state"]),
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

// Generated contract-valid incomplete report from the pinned compiler.
import type { QualityReport } from "./quality-types";

export const qualityFixture = {
  "schema_version": "0.1",
  "report_version": "foundry-quality-0.1",
  "report_id": "quality_907bef2e74d6690016ef737ec4120aef",
  "report_hash": "sha256:907bef2e74d6690016ef737ec4120aefa79840e3c8ac133e12474875be1c613a",
  "rule_version_id": "version_5e23aa81b78406ea9d34298b9c8aaf93",
  "rule_semantic_hash": "sha256:322da0c250b1b6c0f8fd1bfb9d38efbf6602314509eb5382fc3d906259e47fa7",
  "evidence_snapshot_hash": "sha256:66d17288bf3077c2bd8ba8641e7a43bf476198cbef403ccab0e93e3428da71a4",
  "status": "incomplete",
  "required_passed": 9,
  "required_total": 10,
  "optional_unavailable": 4,
  "stages": [
    {
      "stage_id": "access_analyzer",
      "validator_version": "not-installed",
      "corpus_version": "iam-corpus-0.2",
      "status": "unavailable",
      "required": false,
      "duration_ms": null,
      "findings": [
        {
          "code": "validator_finding",
          "message": "tool is not installed",
          "severity": "info",
          "evidence_refs": [
            "evidence_31da0ecf65c6f3a07b5f908a9113d897"
          ]
        }
      ],
      "scenarios": [],
      "evidence_refs": [
        "evidence_31da0ecf65c6f3a07b5f908a9113d897"
      ]
    },
    {
      "stage_id": "aws_action_resource",
      "validator_version": "foundry-validators-0.1",
      "corpus_version": "iam-corpus-0.2",
      "status": "pass",
      "required": true,
      "duration_ms": null,
      "findings": [],
      "scenarios": [],
      "evidence_refs": [
        "evidence_31da0ecf65c6f3a07b5f908a9113d897"
      ]
    },
    {
      "stage_id": "cloudsplaining",
      "validator_version": "not-installed",
      "corpus_version": "iam-corpus-0.2",
      "status": "unavailable",
      "required": false,
      "duration_ms": null,
      "findings": [
        {
          "code": "validator_finding",
          "message": "tool is not installed",
          "severity": "info",
          "evidence_refs": [
            "evidence_31da0ecf65c6f3a07b5f908a9113d897"
          ]
        }
      ],
      "scenarios": [],
      "evidence_refs": [
        "evidence_31da0ecf65c6f3a07b5f908a9113d897"
      ]
    },
    {
      "stage_id": "condition_keys",
      "validator_version": "foundry-validators-0.1",
      "corpus_version": "iam-corpus-0.2",
      "status": "pass",
      "required": true,
      "duration_ms": null,
      "findings": [
        {
          "code": "validator_finding",
          "message": "This candidate declares no condition key",
          "severity": "info",
          "evidence_refs": [
            "evidence_31da0ecf65c6f3a07b5f908a9113d897"
          ]
        }
      ],
      "scenarios": [],
      "evidence_refs": [
        "evidence_31da0ecf65c6f3a07b5f908a9113d897"
      ]
    },
    {
      "stage_id": "contradiction",
      "validator_version": "foundry-validators-0.1",
      "corpus_version": "iam-corpus-0.2",
      "status": "pass",
      "required": true,
      "duration_ms": null,
      "findings": [],
      "scenarios": [],
      "evidence_refs": [
        "evidence_31da0ecf65c6f3a07b5f908a9113d897"
      ]
    },
    {
      "stage_id": "determinism",
      "validator_version": "foundry-validators-0.1",
      "corpus_version": "iam-corpus-0.2",
      "status": "pass",
      "required": true,
      "duration_ms": null,
      "findings": [],
      "scenarios": [],
      "evidence_refs": [
        "evidence_31da0ecf65c6f3a07b5f908a9113d897"
      ]
    },
    {
      "stage_id": "engine3_not_approved",
      "validator_version": "foundry-validators-0.1",
      "corpus_version": "iam-corpus-0.2",
      "status": "pass",
      "required": true,
      "duration_ms": null,
      "findings": [],
      "scenarios": [],
      "evidence_refs": [
        "evidence_31da0ecf65c6f3a07b5f908a9113d897"
      ]
    },
    {
      "stage_id": "evidence_sufficiency",
      "validator_version": "foundry-validators-0.1",
      "corpus_version": "iam-corpus-0.2",
      "status": "pass",
      "required": true,
      "duration_ms": null,
      "findings": [],
      "scenarios": [],
      "evidence_refs": [
        "evidence_31da0ecf65c6f3a07b5f908a9113d897"
      ]
    },
    {
      "stage_id": "ontology",
      "validator_version": "not-recorded",
      "corpus_version": null,
      "status": "skipped",
      "required": true,
      "duration_ms": null,
      "findings": [
        {
          "code": "missing_required_check",
          "message": "No result was recorded for this required check.",
          "severity": "warning",
          "evidence_refs": []
        }
      ],
      "scenarios": [],
      "evidence_refs": []
    },
    {
      "stage_id": "parliament",
      "validator_version": "not-installed",
      "corpus_version": "iam-corpus-0.2",
      "status": "unavailable",
      "required": false,
      "duration_ms": null,
      "findings": [
        {
          "code": "validator_finding",
          "message": "tool is not installed",
          "severity": "info",
          "evidence_refs": [
            "evidence_31da0ecf65c6f3a07b5f908a9113d897"
          ]
        }
      ],
      "scenarios": [],
      "evidence_refs": [
        "evidence_31da0ecf65c6f3a07b5f908a9113d897"
      ]
    },
    {
      "stage_id": "pmapper",
      "validator_version": "not-installed",
      "corpus_version": "iam-corpus-0.2",
      "status": "unavailable",
      "required": false,
      "duration_ms": null,
      "findings": [
        {
          "code": "validator_finding",
          "message": "tool is not installed",
          "severity": "info",
          "evidence_refs": [
            "evidence_31da0ecf65c6f3a07b5f908a9113d897"
          ]
        }
      ],
      "scenarios": [],
      "evidence_refs": [
        "evidence_31da0ecf65c6f3a07b5f908a9113d897"
      ]
    },
    {
      "stage_id": "provenance",
      "validator_version": "foundry-validators-0.1",
      "corpus_version": "iam-corpus-0.2",
      "status": "pass",
      "required": true,
      "duration_ms": null,
      "findings": [],
      "scenarios": [],
      "evidence_refs": [
        "evidence_31da0ecf65c6f3a07b5f908a9113d897"
      ]
    },
    {
      "stage_id": "scenario_corpus",
      "validator_version": "foundry-validators-0.1",
      "corpus_version": "iam-corpus-0.2",
      "status": "pass",
      "required": true,
      "duration_ms": null,
      "findings": [],
      "scenarios": [
        {
          "scenario_id": "allow-create-access-key",
          "case_class": "positive",
          "expect": "match",
          "actual": "match",
          "result": "pass"
        },
        {
          "scenario_id": "explicit-deny-create-access-key",
          "case_class": "near_negative",
          "expect": "no_match",
          "actual": "no_match",
          "result": "pass"
        },
        {
          "scenario_id": "list-access-keys-only",
          "case_class": "near_negative",
          "expect": "no_match",
          "actual": "no_match",
          "result": "pass"
        },
        {
          "scenario_id": "non-user-target",
          "case_class": "near_negative",
          "expect": "no_match",
          "actual": "no_match",
          "result": "pass"
        },
        {
          "scenario_id": "target-type-unknown",
          "case_class": "missing_context",
          "expect": "inconclusive",
          "actual": "inconclusive",
          "result": "pass"
        },
        {
          "scenario_id": "wildcard-action-unsupported",
          "case_class": "adversarial",
          "expect": "inconclusive",
          "actual": "inconclusive",
          "result": "pass"
        }
      ],
      "evidence_refs": [
        "evidence_31da0ecf65c6f3a07b5f908a9113d897"
      ]
    },
    {
      "stage_id": "schema",
      "validator_version": "foundry-validators-0.1",
      "corpus_version": "iam-corpus-0.2",
      "status": "pass",
      "required": true,
      "duration_ms": null,
      "findings": [],
      "scenarios": [],
      "evidence_refs": [
        "evidence_31da0ecf65c6f3a07b5f908a9113d897"
      ]
    }
  ]
} satisfies QualityReport;

"""Build the committed foundry pins from local downloads. This is not a request path."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

_OUT = Path(__file__).resolve().parents[1] / "src" / "fyp_iam" / "engine1" / "foundry" / "pins"
_TEMP = Path(os.environ["FYP_PIN_DIR"])
_ARN = re.compile(r"arn:aws:|\b\d{12}\b", re.IGNORECASE)
_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_ACTION = re.compile(r"\biam:[A-Za-z]+\b")
_WANTED = ("T1098", "T1098.001", "T1098.003", "T1548")
_IAM_ACTIONS = (
    "CreateAccessKey",
    "UpdateAssumeRolePolicy",
    "CreateRole",
    "AttachRolePolicy",
    "ListAccessKeys",
    "GetRole",
)


def main() -> None:
    _OUT.mkdir(parents=True, exist_ok=True)
    mitre_name = _write("mitre-enterprise-19.2-extract.json", _mitre())
    aws_name = _write("aws-service-reference-extract.json", _aws())
    stratus_name = _write("stratus-iam-redacted.json", _stratus())
    files = {
        "stix": mitre_name,
        "aws": aws_name,
        "stratus": stratus_name,
    }
    manifest = {
        "files": [
            {"name": name, "role": role, "sha256": _hash(_OUT / name)}
            for role, name in files.items()
        ],
        "sources": [
            _source(
                "mitre-attack",
                1,
                "taxonomy",
                "https://github.com/mitre-attack/attack-stix-data",
                "19.2",
                mitre_name,
            ),
            _source(
                "aws-service-reference",
                1,
                "service_reference",
                "https://servicereference.us-east-1.amazonaws.com/v1/service-list.json",
                "v1.4",
                aws_name,
            ),
            _source(
                "stratus-red-team",
                2,
                "community_behavior",
                "https://github.com/DataDog/stratus-red-team",
                "redacted-field-extract-0.1",
                stratus_name,
            ),
        ],
    }
    encoded = json.dumps(manifest, indent=2).encode("utf-8") + b"\n"
    if _ARN.search(encoded.decode("utf-8")):
        raise SystemExit("manifest contains a forbidden marker")
    (_OUT / "manifest.json").write_bytes(encoded)
    print("wrote", _OUT)


def _mitre() -> dict[str, object]:
    raw = (_TEMP / "enterprise-attack-19.2.json").read_bytes()
    document = json.loads(raw)
    objects = []
    for item in document["objects"]:
        if item.get("type") != "attack-pattern":
            continue
        external = ""
        for ref in item.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                external = ref.get("external_id", "")
        if external not in _WANTED:
            continue
        kept_refs = [
            {
                "source_name": "mitre-attack",
                "external_id": external,
                "url": ref.get("url", ""),
            }
            for ref in item.get("external_references", [])
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id") == external
        ]
        objects.append(
            {
                "type": "attack-pattern",
                "name": item.get("name", ""),
                "external_references": kept_refs,
                "x_mitre_platforms": item.get("x_mitre_platforms", []),
            }
        )
    objects.sort(key=lambda row: str(row["name"]))
    if len(objects) != len(_WANTED):
        raise SystemExit(f"expected {len(_WANTED)} techniques, found {len(objects)}")
    return {
        "type": "bundle",
        "id": "bundle--foundry-enterprise-19.2-extract",
        "spec_version": "2.1",
        "objects": objects,
        "parent_collection_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "parent_version": "19.2",
    }


def _aws() -> dict[str, object]:
    services = []
    for filename, prefix in (("iam.json", "iam"), ("sts.json", "sts")):
        document = json.loads((_TEMP / filename).read_text(encoding="utf-8"))
        wanted = _IAM_ACTIONS if prefix == "iam" else ("AssumeRole",)
        actions = []
        for action in document["Actions"]:
            if action["Name"] not in wanted:
                continue
            actions.append(
                {
                    "name": action["Name"],
                    "resources": [item["Name"] for item in action["Resources"]],
                }
            )
        actions.sort(key=lambda row: str(row["name"]))
        services.append({"prefix": prefix, "version": document["Version"], "actions": actions})
    return {"services": services}


def _stratus() -> dict[str, object]:
    specs = (
        ("aws.persistence.iam-backdoor-user.md", "Create an Access Key on an IAM User"),
        ("aws.persistence.iam-backdoor-role.md", "Backdoor an IAM Role"),
        ("aws.persistence.iam-create-backdoor-role.md", "Create a backdoored IAM Role"),
    )
    techniques = []
    originals = []
    for filename, title in specs:
        raw = (_TEMP / filename).read_bytes()
        originals.append("sha256:" + hashlib.sha256(raw).hexdigest())
        text = raw.decode("utf-8")
        technique_id = filename.removesuffix(".md")
        actions = sorted(set(_ACTION.findall(text)))
        event_names = {
            "UpdateAssumeRolePolicy": "iam:UpdateAssumeRolePolicy",
            "CreateAccessKey": "iam:CreateAccessKey",
            "CreateRole": "iam:CreateRole",
            "AttachRolePolicy": "iam:AttachRolePolicy",
        }
        for label, action in event_names.items():
            if label in text and action not in actions:
                actions.append(action)
        cited = sorted(set(_TECH.findall(text.split("## Description", 1)[0])))
        techniques.append(
            {
                "id": technique_id,
                "title": title,
                "actions": sorted(set(actions)),
                "cited_technique_ids": cited,
            }
        )
    payload = {
        "redaction": "Example ARN text and account ids were removed before this file was written.",
        "original_sha256": originals,
        "techniques": techniques,
    }
    if _ARN.search(json.dumps(payload)):
        raise SystemExit("redacted stratus pin still has a forbidden marker")
    return payload


def _source(
    key: str,
    tier: int,
    source_type: str,
    url: str,
    label: str,
    filename: str,
) -> dict[str, object]:
    return {
        "source_key": key,
        "authority_tier": tier,
        "source_type": source_type,
        "official_url": url,
        "version_label": label,
        "content_hash": _hash(_OUT / filename),
    }


def _write(name: str, payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, indent=2).encode("utf-8") + b"\n"
    if _ARN.search(encoded.decode("utf-8")):
        raise SystemExit(f"{name} contains a forbidden marker")
    (_OUT / name).write_bytes(encoded)
    return name


def _hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    main()

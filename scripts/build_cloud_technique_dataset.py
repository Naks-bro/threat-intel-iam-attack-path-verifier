"""Build a 50-row cloud technique dataset from a local Enterprise ATT&CK STIX file.

The runtime loader does not call this script and does not download ATT&CK.
Pass the already saved enterprise-attack-19.2.json path.
"""

import hashlib
import json
import re
from pathlib import Path

_COLLECTION_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-19.2.json"
)
_SOURCE_VERSION = "19.2"
_RETRIEVED_AT = "2026-10-02T17:19:56Z"
_COLLECTION_MODIFIED = "2026-08-05T21:33:58.496Z"
_PRIMARY = frozenset({"IaaS"})
_SECONDARY = frozenset(
    {"SaaS", "Office 365", "Google Workspace", "Azure AD", "Identity Provider", "Containers"}
)
_ID = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_LIMIT = 50


def technique_reference(external_id: str) -> str:
    if "." in external_id:
        parent, child = external_id.split(".", maxsplit=1)
        return f"https://attack.mitre.org/techniques/{parent}/{child}/"
    return f"https://attack.mitre.org/techniques/{external_id}/"


def _external_id(obj: dict[str, object]) -> str | None:
    refs = obj.get("external_references")
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        if ref.get("source_name") != "mitre-attack":
            continue
        value = ref.get("external_id")
        if isinstance(value, str) and _ID.fullmatch(value):
            return value
    return None


def _tactics(obj: dict[str, object]) -> list[str]:
    phases = obj.get("kill_chain_phases")
    if not isinstance(phases, list):
        return []
    names: set[str] = set()
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        if phase.get("kill_chain_name") != "mitre-attack":
            continue
        name = phase.get("phase_name")
        if isinstance(name, str) and name:
            names.add(name)
    return sorted(names)


def _platforms(obj: dict[str, object]) -> list[str]:
    raw = obj.get("x_mitre_platforms")
    if not isinstance(raw, list):
        return []
    return sorted(str(item) for item in raw if isinstance(item, str))


def select_records(
    objects: list[dict[str, object]],
) -> tuple[list[dict[str, object]], dict[str, int]]:
    primary: list[dict[str, object]] = []
    secondary: list[dict[str, object]] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
            continue
        external_id = _external_id(obj)
        name = obj.get("name")
        stix_id = obj.get("id")
        if external_id is None or not isinstance(name, str) or not isinstance(stix_id, str):
            continue
        platforms = _platforms(obj)
        platform_set = set(platforms)
        row = {
            "external_id": external_id,
            "name": name,
            "platforms": platforms,
            "stix_id": stix_id,
            "tactics": _tactics(obj),
            "official_reference": technique_reference(external_id),
        }
        if platform_set & _PRIMARY:
            primary.append(row)
        elif platform_set & _SECONDARY:
            secondary.append(row)
    primary.sort(key=lambda item: str(item["external_id"]))
    secondary.sort(key=lambda item: str(item["external_id"]))
    chosen = (primary + secondary)[:_LIMIT]
    chosen.sort(key=lambda item: str(item["external_id"]))
    counts = {
        "iaas": len(primary),
        "other_cloud": len(secondary),
        "selected": len(chosen),
    }
    return chosen, counts


def build(source: Path, destination: Path) -> None:
    raw = source.read_bytes()
    bundle = json.loads(raw)
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise SystemExit("STIX bundle has no objects")
    records, counts = select_records(objects)
    if len(records) != _LIMIT:
        raise SystemExit(f"expected {_LIMIT} records, found {counts}")
    payload = {
        "collection_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "collection_url": _COLLECTION_URL,
        "dataset_id": "mitre-enterprise-cloud-50",
        "license_note": (
            "Identifiers and names cite MITRE ATT&CK Enterprise 19.2. "
            "Technique descriptions were not copied. Runtime code does not download this file."
        ),
        "records": records,
        "retrieved_at": _RETRIEVED_AT,
        "schema_version": "0.1",
        "selection": (
            "Not-revoked Enterprise attack-pattern objects with platform IaaS, "
            "then SaaS, Office 365, Google Workspace, Azure AD, Identity Provider, "
            "or Containers. Sorted by technique id and limited to 50. "
            f"Available IaaS rows: {counts['iaas']}. Other cloud rows: {counts['other_cloud']}."
        ),
        "source_name": "mitre-attack",
        "source_version": _SOURCE_VERSION,
        "collection_modified": _COLLECTION_MODIFIED,
    }
    destination.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(counts)
    print(destination)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        raise SystemExit("usage: build_cloud_technique_dataset.py SOURCE.json DEST.json")
    build(Path(sys.argv[1]), Path(sys.argv[2]))

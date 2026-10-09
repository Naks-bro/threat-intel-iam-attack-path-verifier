"""Pinned snapshot loader. Hashes are checked before parse."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parent / "pins"


@dataclass(frozen=True)
class TechniquePin:
    native_id: str
    name: str


@dataclass(frozen=True)
class ActionPin:
    native_id: str
    resources: tuple[str, ...]


@dataclass(frozen=True)
class BehaviorPin:
    native_id: str
    title: str
    actions: tuple[str, ...]
    cited_technique_ids: tuple[str, ...]


@dataclass(frozen=True)
class LoadedPins:
    techniques: dict[str, TechniquePin]
    actions: dict[str, ActionPin]
    behaviors: tuple[BehaviorPin, ...]
    source_rows: list[dict[str, object]]
    bundle_hash: str
    untrusted_text: str
    payloads: dict[str, bytes]


def load_pins() -> LoadedPins:
    manifest_raw = (_ROOT / "manifest.json").read_bytes()
    manifest = _object(json.loads(manifest_raw))
    payloads: dict[str, bytes] = {}
    parsed: dict[str, dict[str, object]] = {}
    for item in _object_list(manifest["files"]):
        name = _text(item["name"])
        raw = (_ROOT / name).read_bytes()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if digest != _text(item["sha256"]):
            raise RuntimeError(f"pinned snapshot hash mismatch for {name}")
        payloads[name] = raw
        parsed[_text(item["role"])] = _object(json.loads(raw))
    sources: list[dict[str, object]] = []
    for item in _object_list(manifest["sources"]):
        sources.append(
            {
                "source_key": _text(item["source_key"]),
                "authority_tier": _int(item["authority_tier"]),
                "source_type": _text(item["source_type"]),
                "official_url": _text(item["official_url"]),
                "version_label": _text(item["version_label"]),
                "enabled": True,
                "content_hash": _text(item["content_hash"]),
            }
        )
    ordered = b"".join(payloads[name] for name in sorted(payloads))
    return LoadedPins(
        techniques=_techniques(parsed["stix"]),
        actions=_actions(parsed["aws"]),
        behaviors=_behaviors(parsed["stratus"]),
        source_rows=sources,
        bundle_hash=hashlib.sha256(ordered).hexdigest(),
        untrusted_text=json.dumps(parsed["stratus"]),
        payloads=payloads,
    )


def _techniques(stix: dict[str, object]) -> dict[str, TechniquePin]:
    found: dict[str, TechniquePin] = {}
    for obj in _object_list(stix["objects"]):
        if obj.get("type") != "attack-pattern":
            continue
        external = ""
        for ref in _object_list(obj.get("external_references", [])):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                external = _text(ref["external_id"])
        if external:
            found[external] = TechniquePin(native_id=external, name=_text(obj.get("name", "")))
    return found


def _actions(document: dict[str, object]) -> dict[str, ActionPin]:
    found: dict[str, ActionPin] = {}
    for service in _object_list(document["services"]):
        prefix = _text(service["prefix"])
        for action in _object_list(service["actions"]):
            native = f"{prefix}:{_text(action['name'])}"
            resources = tuple(_text(item) for item in _list(action["resources"]))
            found[native] = ActionPin(native_id=native, resources=resources)
    return found


def _behaviors(document: dict[str, object]) -> tuple[BehaviorPin, ...]:
    rows: list[BehaviorPin] = []
    for item in _object_list(document["techniques"]):
        rows.append(
            BehaviorPin(
                native_id=_text(item["id"]),
                title=_text(item["title"]),
                actions=tuple(_text(action) for action in _list(item["actions"])),
                cited_technique_ids=tuple(
                    _text(tech) for tech in _list(item["cited_technique_ids"])
                ),
            )
        )
    return tuple(rows)


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError("pinned JSON object is missing")
    return {str(key): item for key, item in value.items()}


def _object_list(value: object) -> list[dict[str, object]]:
    return [_object(item) for item in _list(value)]


def _list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise RuntimeError("pinned JSON list is missing")
    return list(value)


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeError("pinned text is missing")
    return value


def _int(value: object) -> int:
    if not isinstance(value, int):
        raise RuntimeError("pinned integer is missing")
    return value

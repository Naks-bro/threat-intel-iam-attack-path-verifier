"""Derive the small quality-report TypeScript contract from its Pydantic schema.

No network, secrets, arbitrary reference resolution, or file writes. --check
compares the checked-in consumer artifact with the current provider schema.
"""

import argparse
import json
from pathlib import Path
from typing import Any

from fyp_iam.engine1.foundry.quality import QualityReport

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "frontend" / "src" / "generated" / "quality-types.ts"
FIXTURE_TARGET = TARGET.with_name("quality-fixture.ts")


def _type(schema: dict[str, Any]) -> str:
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            raise ValueError("only local schema definitions are allowed")
        return str(ref.rsplit("/", 1)[-1])
    if "const" in schema:
        return repr(schema["const"]).replace("'", '"')
    if "enum" in schema:
        return " | ".join(repr(value).replace("'", '"') for value in schema["enum"])
    if "anyOf" in schema:
        return " | ".join(_type(item) for item in schema["anyOf"])
    kind = schema.get("type")
    if kind == "array":
        return f"Array<{_type(schema['items'])}>"
    if kind in {"integer", "number"}:
        return "number"
    if kind in {"string", "boolean", "null"}:
        return str(kind)
    raise ValueError(f"unsupported quality-contract schema type: {kind}")


def generated_types() -> str:
    schema = QualityReport.model_json_schema()
    definitions = {**schema.get("$defs", {}), "QualityReport": schema}
    lines = ["// Generated from QualityReport.model_json_schema(); do not edit by hand."]
    for name, body in sorted(definitions.items()):
        lines.extend(["", f"export type {name} = {{"])
        required = body.get("required", [])
        for key, value in body["properties"].items():
            optional = "" if key in required else "?"
            lines.append(f"  {key}{optional}: {_type(value)};")
        lines.append("};")
    return "\n".join(lines) + "\n"


def generated_fixture() -> str:
    from fyp_iam.engine1.foundry.pipeline import build_foundry
    from fyp_iam.engine1.foundry.quality import build_quality_report

    result = build_foundry(persisted=False, storage="not_written")
    candidate = result["candidate"]
    rows = result["validations"]
    if not isinstance(candidate, dict) or not isinstance(rows, list):
        raise ValueError("pinned fixture candidate missing")
    report = build_quality_report(
        candidate, [row for row in rows if row["validator_name"] != "ontology"]
    )
    encoded = json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False)
    return (
        "// Generated contract-valid incomplete report from the pinned compiler.\n"
        'import type { QualityReport } from "./quality-types";\n\n'
        f"export const qualityFixture = {encoded} satisfies QualityReport;\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--fixture", action="store_true")
    arguments = parser.parse_args()
    expected = generated_fixture() if arguments.fixture else generated_types()
    target = FIXTURE_TARGET if arguments.fixture else TARGET
    if arguments.check:
        if not target.exists() or target.read_text(encoding="utf-8") != expected:
            print(f"Quality consumer contract is stale. Regenerate and review {target.name}.")
            return 1
        print("Quality consumer contract matches the provider schema.")
    else:
        print(expected, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

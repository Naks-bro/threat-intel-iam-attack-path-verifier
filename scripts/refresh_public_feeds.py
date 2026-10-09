"""Download the free NVD page and CISA KEV catalog into minimized pins.

Runtime loaders do not call this script. It needs network access and an
optional NVD API key is not used. Re-run only when a maintainer intends to
refresh the pins, then update the SHA-256 constants in opportunities.py.
"""

import hashlib
import json
import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.request import Request, urlopen

_ROOT = Path(__file__).resolve().parents[1]
_ARTIFACTS = _ROOT / "src" / "fyp_iam" / "engine1" / "artifacts"
_NVD_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=AWS%20IAM&resultsPerPage=5"
)
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_PRODUCT = re.compile(r"(^|[^A-Za-z])(amazon|aws)([^A-Za-z]|$)")
_UA = {"User-Agent": "fyp-iam-local-dataset"}


def _get(url: str) -> tuple[bytes, datetime]:
    with urlopen(Request(url, headers=_UA), timeout=120) as response:
        retrieved = parsedate_to_datetime(response.headers["Date"]).astimezone(UTC)
        return response.read(), retrieved


def _write(name: str, payload: dict[str, object]) -> None:
    path = _ARTIFACTS / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f"{name} sha256:{digest}")


def refresh_nvd() -> None:
    raw, retrieved = _get(_NVD_URL)
    data = json.loads(raw)
    records = []
    for item in data.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cve_id = str(cve.get("id", ""))
        records.append(
            {
                "cve_id": cve_id,
                "official_reference": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published": cve.get("published"),
            }
        )
    records.sort(key=lambda row: str(row["cve_id"]))
    _write(
        "nvd-aws-iam-page.json",
        {
            "api_key_used": False,
            "keyword_search": "AWS IAM",
            "license_note": (
                "NVD CVE API 2.0 page. Descriptions are not stored. "
                "A keyword hit is not a technique mapping."
            ),
            "records": records,
            "request_url": _NVD_URL,
            "results_per_page": data.get("resultsPerPage"),
            "retrieved_at": retrieved.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "schema_version": "0.1",
            "source_name": "nvd",
            "total_results": data.get("totalResults"),
        },
    )


def refresh_kev() -> None:
    raw, retrieved = _get(_KEV_URL)
    data = json.loads(raw)
    matched: list[str] = []
    for item in data.get("vulnerabilities") or []:
        blob = f"{item.get('vendorProject', '')} {item.get('product', '')}".lower()
        if _PRODUCT.search(blob):
            matched.append(str(item.get("cveID", "")))
    matched.sort()
    _write(
        "cisa-kev-catalog.json",
        {
            "catalog_version": data.get("catalogVersion"),
            "date_released": data.get("dateReleased"),
            "feed_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "feed_url": _KEV_URL,
            "license_note": (
                "CISA Known Exploited Vulnerabilities JSON feed. "
                "Vulnerability bodies are not stored."
            ),
            "matched_cve_ids": matched,
            "product_filter": "vendor or product contains Amazon or AWS as a whole token",
            "retrieved_at": retrieved.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "schema_version": "0.1",
            "source_name": "cisa-kev",
            "vulnerability_count": data.get("count"),
        },
    )


if __name__ == "__main__":
    refresh_nvd()
    refresh_kev()

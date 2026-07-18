#!/usr/bin/env python3
"""Build data/notes_catalog.json from the SAP Security Notes xlsx export.

Usage:
    python scripts/build_catalog.py [path/to/export.xlsx] [--offline]

Input columns (SAP "Security Notes" export):
    SAP Component | Number | Title | CVSS Score | CVSS Vector | Category |
    Priority | Released On | First Released On | Link

Rules (see README "Data sources & honesty"):
- The catalog contains ONLY public metadata. No note body text is ever
  fetched or included. Fields that cannot be filled from the input file or
  a public source are set to null — never fabricated.
- Exploitation data comes from the public CISA KEV feed, cached in
  data/kev_snapshot.json so builds are reproducible offline (--offline or
  network failure falls back to the snapshot).
- Every record is validated against data/schema.json; violations abort the
  build with a non-zero exit code.
"""

import json
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import openpyxl

try:
    import jsonschema
except ImportError:
    jsonschema = None

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
KEV_SNAPSHOT = DATA_DIR / "kev_snapshot.json"
SCHEMA_PATH = DATA_DIR / "schema.json"
CATALOG_PATH = DATA_DIR / "notes_catalog.json"

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

EXPECTED_COLUMNS = [
    "SAP Component", "Number", "Title", "CVSS Score", "CVSS Vector",
    "Category", "Priority", "Released On", "First Released On", "Link",
]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
BRACKET_PREFIX_RE = re.compile(r"^\s*\[[^\]]*\]\s*")
# A well-formed CVSS v3.x vector starts with an explicit version segment.
CVSS_VECTOR_RE = re.compile(r"^CVSS:\d+\.\d+/AV:")


def normalize_priority(raw: str) -> str:
    """Map SAP's priority strings onto HotNews/High/Medium/Low."""
    lowered = (raw or "").strip().lower()
    if "hotnews" in lowered or "hot news" in lowered:
        return "HotNews"
    if "high" in lowered:
        return "High"
    if "medium" in lowered:
        return "Medium"
    if "low" in lowered:
        return "Low"
    raise ValueError(f"Unrecognized priority string: {raw!r}")


def to_iso_date(value) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    # String fallback, e.g. "2026-07-14" or "14.07.2026"
    text = str(value).strip()
    for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%m/%d/%Y"):
        try:
            return datetime.strptime(text[:10], fmt).date().isoformat()
        except ValueError:
            continue
    raise ValueError(f"Unparseable date: {value!r}")


def clean_text(value) -> str:
    """Collapse non-breaking spaces and stray whitespace."""
    return re.sub(r"\s+", " ", str(value).replace("\xa0", " ")).strip()


def load_kev(offline: bool) -> dict:
    """Return the KEV feed, refreshing the snapshot when online.

    The snapshot file wraps the feed with a fetched-date field so catalog
    builds are reproducible without network access.
    """
    if not offline:
        try:
            import httpx

            resp = httpx.get(KEV_FEED_URL, timeout=60, follow_redirects=True)
            resp.raise_for_status()
            feed = resp.json()
            snapshot = {
                "fetched": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "source": KEV_FEED_URL,
                "feed": feed,
            }
            KEV_SNAPSHOT.write_text(json.dumps(snapshot, indent=1))
            print(f"KEV feed refreshed: version {feed.get('catalogVersion')}, "
                  f"{feed.get('count')} CVEs")
            return snapshot
        except Exception as exc:  # noqa: BLE001 — fall back to snapshot
            print(f"WARNING: KEV download failed ({exc}); using cached snapshot")

    if KEV_SNAPSHOT.exists():
        snapshot = json.loads(KEV_SNAPSHOT.read_text())
        print(f"Using cached KEV snapshot fetched {snapshot.get('fetched')}")
        return snapshot

    print("ERROR: no KEV feed available (offline and no snapshot). "
          "Run once with network access first.")
    sys.exit(1)


def build_records(xlsx_path: Path, kev_by_cve: dict) -> list[dict]:
    wb = openpyxl.load_workbook(xlsx_path, data_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=True))
    header = [clean_text(h) for h in rows[0]]
    if header != EXPECTED_COLUMNS:
        raise SystemExit(f"Unexpected columns: {header}")

    records = []
    for row in rows[1:]:
        if row[1] is None:  # trailing blank row
            continue
        raw = dict(zip(EXPECTED_COLUMNS, row))
        raw_title = clean_text(raw["Title"])

        cve_ids = sorted(set(CVE_RE.findall(raw_title)))
        multiple_cves = "[multiple cves]" in raw_title.lower()
        title = BRACKET_PREFIX_RE.sub("", raw_title).strip()

        cvss_raw = raw["CVSS Score"]
        cvss_score = float(cvss_raw) if cvss_raw is not None else None
        if cvss_score == 0.0:
            # SAP publishes some notes (e.g. advisories) with CVSS 0.0,
            # which is "not scored", not "zero risk" — record as null.
            cvss_score = None

        vector = clean_text(raw["CVSS Vector"]) if raw["CVSS Vector"] else None
        vector_malformed = bool(vector) and not CVSS_VECTOR_RE.match(vector)

        released_on = to_iso_date(raw["Released On"])
        first_released_on = to_iso_date(raw["First Released On"])
        is_update = bool(
            first_released_on and released_on and first_released_on < released_on
        )

        note_number = str(raw["Number"]).strip()
        link = clean_text(raw["Link"]) if raw["Link"] else ""
        note_url = link or f"https://me.sap.com/notes/{note_number}"

        kev_hits = [kev_by_cve[c] for c in cve_ids if c in kev_by_cve]
        kev_listed = bool(kev_hits)
        kev_date_added = min(h.get("dateAdded") for h in kev_hits) if kev_hits else None

        record = {
            "note_number": note_number,
            "title": title,
            "cve_ids": cve_ids,
            "cvss_score": cvss_score,
            "cvss_vector": vector,
            "priority": normalize_priority(raw["Priority"]),
            "priority_raw": clean_text(raw["Priority"]),
            "category": clean_text(raw["Category"]) if raw["Category"] else None,
            "component": clean_text(raw["SAP Component"]),
            "release_month": released_on[:7],
            "released_on": released_on,
            "first_released_on": first_released_on,
            "is_update": is_update,
            "kev_listed": kev_listed,
            "kev_date_added": kev_date_added,
            "note_url": note_url,
        }
        if multiple_cves:
            record["multiple_cves"] = True
        if vector_malformed:
            record["cvss_vector_malformed"] = True
        records.append(record)

    return records


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    offline = "--offline" in sys.argv

    if args:
        xlsx_path = Path(args[0])
    else:
        candidates = sorted((REPO_ROOT / "input").glob("security-notes-result-*.xlsx"))
        if not candidates:
            raise SystemExit("No xlsx found in input/ and no path given")
        xlsx_path = candidates[-1]
    print(f"Input: {xlsx_path}")

    snapshot = load_kev(offline)
    kev_by_cve = {
        v["cveID"]: v for v in snapshot["feed"].get("vulnerabilities", [])
    }

    records = build_records(xlsx_path, kev_by_cve)
    records.sort(key=lambda r: (r["released_on"], r["note_number"]), reverse=True)

    months = sorted({r["release_month"] for r in records})
    # Catalog version is date-based, taken from the export filename
    # (security-notes-result-YYYYMMDD.xlsx) so rebuilds are reproducible.
    m = re.search(r"(\d{4})(\d{2})(\d{2})", xlsx_path.name)
    catalog_version = (
        f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else snapshot.get("fetched")
    )

    catalog = {
        "catalog_meta": {
            "catalog_version": catalog_version,
            "note_count": len(records),
            "coverage_start": months[0],
            "coverage_end": months[-1],
            "source_statement": (
                "Metadata from SAP Security Patch Day publications; "
                "exploitation data from CISA KEV"
            ),
            "kev_snapshot_version": snapshot["feed"].get("catalogVersion"),
            "kev_snapshot_fetched": snapshot.get("fetched"),
        },
        "notes": records,
    }

    if jsonschema is None:
        raise SystemExit("jsonschema is required to build the catalog "
                         "(pip install jsonschema) — validation is mandatory")
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(catalog), key=lambda e: list(e.path))
    if errors:
        for err in errors:
            path = "/".join(str(p) for p in err.path)
            print(f"SCHEMA VIOLATION at {path}: {err.message}")
        raise SystemExit(f"{len(errors)} schema violation(s) — catalog NOT written")

    CATALOG_PATH.write_text(json.dumps(catalog, indent=1) + "\n")
    kev_count = sum(1 for r in records if r["kev_listed"])
    print(f"Wrote {CATALOG_PATH}: {len(records)} notes, "
          f"{months[0]} → {months[-1]}, {kev_count} KEV-listed")


if __name__ == "__main__":
    main()

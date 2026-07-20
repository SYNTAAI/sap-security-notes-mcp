#!/usr/bin/env python3
"""Ongoing monthly pipeline: add one new SAP Security Patch Day page and
rebuild the catalog.

Usage:
    python scripts/monthly_update.py <page-url-or-local-html> [--month YYYY-MM]

Steps: fetch/cache the page -> parse it (with every previously cached
month, since a note's canonical record can change on a later page) ->
re-run KEV enrichment -> validate against data/schema.json -> run the CI
disposition gate (fails loudly if a new, undispositioned application
component appeared) -> write data/notes_catalog.json -> print a summary
suitable for the Patch Tuesday commit message / post.

This never hand-patches notes_catalog.json -- it is always a fresh
rebuild from ALL cached pages in data/pages/.
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_catalog import load_kev  # noqa: E402
from catalog_builder import (  # noqa: E402
    build_catalog_from_pages, load_cached_pages,
)
from parse_patchday_page import load_page, month_from_url  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
PAGES_DIR = DATA_DIR / "pages"
SCHEMA_PATH = DATA_DIR / "schema.json"
CATALOG_PATH = DATA_DIR / "notes_catalog.json"


def run_disposition_gate() -> bool:
    print("\nRunning CI disposition gate "
          "(every catalog component must be mapped/excluded/unmapped)...")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q",
         "tests/test_taxonomy.py::test_every_catalog_component_has_explicit_disposition"],
        cwd=REPO_ROOT,
    )
    return result.returncode == 0


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        raise SystemExit(__doc__)
    source = args[0]
    month_override = None
    if "--month" in sys.argv:
        month_override = sys.argv[sys.argv.index("--month") + 1]

    page_html, source_url = load_page(source)
    month = month_override or month_from_url(source_url)
    PAGES_DIR.mkdir(parents=True, exist_ok=True)
    (PAGES_DIR / f"{month}.html").write_text(page_html)
    print(f"Cached {source_url} -> data/pages/{month}.html")

    old_catalog = json.loads(CATALOG_PATH.read_text())
    old_notes_by_number = {n["note_number"]: n for n in old_catalog["notes"]}

    snapshot = load_kev(offline=False)
    kev_by_cve = {v["cveID"]: v for v in snapshot["feed"].get("vulnerabilities", [])}

    pages = load_cached_pages(PAGES_DIR)
    notes, discrepancies, coverage = build_catalog_from_pages(
        pages, kev_by_cve, old_notes_by_number
    )

    c = coverage[month]
    print(f"\n{month}: {c['total']} rows, {c['parsed']} parsed, "
          f"{c['unparsed']} unparsed {c['unparsed_notes']}")

    records = sorted(
        notes.values(),
        key=lambda r: (r["released_on"] or r["release_month"] + "-01",
                       r["note_number"]),
        reverse=True,
    )
    months = sorted({r["release_month"] for r in records})

    catalog = {
        "catalog_meta": {
            **old_catalog["catalog_meta"],
            "catalog_version": month + "-01",  # bumped by caller if desired
            "note_count": len(records),
            "coverage_start": months[0],
            "coverage_end": months[-1],
            "kev_snapshot_version": snapshot["feed"].get("catalogVersion"),
            "kev_snapshot_fetched": snapshot.get("fetched"),
        },
        "notes": records,
    }

    import jsonschema
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(catalog), key=lambda e: list(e.path))
    if errors:
        for err in errors:
            path = "/".join(str(p) for p in err.path)
            print(f"SCHEMA VIOLATION at {path}: {err.message}")
        raise SystemExit(f"{len(errors)} schema violation(s) -- catalog NOT written")

    CATALOG_PATH.write_text(json.dumps(catalog, indent=1) + "\n")
    print(f"Wrote {CATALOG_PATH}: {len(records)} notes")

    if not run_disposition_gate():
        print("\nDISPOSITION GATE FAILED: a new application component has "
              "no explicit mapping decision. The catalog was written, but "
              "commit is blocked until data/component_mapping.yaml is "
              "updated (mapped / excluded / listed under unmapped) and "
              "reviewed. Do not push.")
        raise SystemExit(1)
    print("Disposition gate passed.")

    new_notes = [r for r in records if r["release_month"] == month]
    hot = [r for r in new_notes if r["priority"] == "HotNews"]
    kev = [r for r in records if r["kev_listed"]]

    print("\n" + "=" * 60)
    print(f"PATCH TUESDAY SUMMARY -- {month}")
    print("=" * 60)
    print(f"Total notes this month: {len(new_notes)}")
    print(f"HotNews: {len(hot)}")
    for r in hot:
        print(f"  - {r['note_number']} (CVSS {r['cvss_score']}): {r['title']}")
    print(f"Catalog now covers {months[0]} -> {months[-1]}, "
          f"{len(records)} notes total, {len(kev)} KEV-listed.")
    print(f"Discrepancies vs. previous build: {len(discrepancies)}")


if __name__ == "__main__":
    main()

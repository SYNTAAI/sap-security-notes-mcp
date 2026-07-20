#!/usr/bin/env python3
"""v2.1 one-time backfill: rebuild data/notes_catalog.json from the public
SAP Security Patch Day pages (Jan-Jul 2026) as PRIMARY source, using the
prior xlsx-derived catalog only as a cross-check.

Usage:
    python scripts/backfill_from_pages.py [--offline]

Writes:
    data/notes_catalog.json          (rebuilt)
    reports/v21_backfill_discrepancies.md
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_catalog import load_kev  # noqa: E402
from catalog_builder import build_catalog_from_pages, load_cached_pages  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
PAGES_DIR = DATA_DIR / "pages"
SCHEMA_PATH = DATA_DIR / "schema.json"
CATALOG_PATH = DATA_DIR / "notes_catalog.json"
REPORTS_DIR = REPO_ROOT / "reports"


def write_discrepancy_report(discrepancies: list[dict], coverage: dict) -> None:
    lines = [
        "# v2.1 Backfill Discrepancy Report",
        "",
        "Catalog rebuilt from public SAP Security Patch Day pages "
        "(Jan-Jul 2026) as primary source, cross-checked against the "
        "prior xlsx-derived catalog.",
        "",
        "## Parse coverage per month",
        "",
        "| Month | Rows | Parsed (affected data) | Unparsed | Unparsed notes |",
        "|---|---|---|---|---|",
    ]
    for month in sorted(coverage):
        c = coverage[month]
        lines.append(
            f"| {month} | {c['total']} | {c['parsed']} | {c['unparsed']} | "
            f"{', '.join(c['unparsed_notes']) or '-'} |"
        )

    added = [d for d in discrepancies if d["kind"] == "added_from_pages"]
    missing = [d for d in discrepancies if d["kind"] == "missing_from_pages"]
    changed = [d for d in discrepancies if d["kind"] == "field_changed"]

    lines += [
        "",
        f"## New notes added from public pages ({len(added)})",
        "",
        "These were on a public Patch Day page but absent from the prior "
        "xlsx export — the xlsx export missed them. Added; `component` "
        "(legacy SAP application component) is null for these since "
        "pages don't publish it — never fabricated. They remain fully "
        "reachable via the affected[] software-component/version data.",
        "",
    ]
    for d in added:
        lines.append(f"- **{d['note_number']}** — {d['detail']}")

    lines += [
        "",
        f"## In prior catalog but not found on any public page ({len(missing)})",
        "",
        "Kept as-is for human review — absence from the pages we fetched "
        "does not mean the note doesn't exist.",
        "",
    ]
    for d in missing:
        lines.append(f"- **{d['note_number']}** — {d['detail']}")

    lines += [
        "",
        f"## Field-level differences: public page wins ({len(changed)})",
        "",
        "| Note | Field | Old (xlsx) | New (public page) |",
        "|---|---|---|---|",
    ]
    for d in changed:
        lines.append(
            f"| {d['note_number']} | {d['field']} | `{d['old_value']}` | "
            f"`{d['new_value']}` |"
        )

    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "v21_backfill_discrepancies.md").write_text(
        "\n".join(lines) + "\n"
    )


def main() -> None:
    offline = "--offline" in sys.argv

    old_catalog = json.loads(CATALOG_PATH.read_text())
    old_notes_by_number = {n["note_number"]: n for n in old_catalog["notes"]}
    print(f"Prior catalog (xlsx-derived, cross-check baseline): "
          f"{len(old_notes_by_number)} notes")

    snapshot = load_kev(offline)
    kev_by_cve = {v["cveID"]: v for v in snapshot["feed"].get("vulnerabilities", [])}

    pages = load_cached_pages(PAGES_DIR)
    print(f"Loaded {len(pages)} cached public pages: {sorted(pages)}")

    notes, discrepancies, coverage = build_catalog_from_pages(
        pages, kev_by_cve, old_notes_by_number
    )

    for month, c in sorted(coverage.items()):
        print(f"{month}: {c['total']} rows, {c['parsed']} parsed, "
              f"{c['unparsed']} unparsed {c['unparsed_notes']}")

    records = sorted(
        notes.values(),
        key=lambda r: (r["released_on"] or r["release_month"] + "-01",
                       r["note_number"]),
        reverse=True,
    )
    months = sorted({r["release_month"] for r in records})
    kev_count = sum(1 for r in records if r["kev_listed"])

    catalog = {
        "catalog_meta": {
            "catalog_version": "2026-07-20",
            "note_count": len(records),
            "coverage_start": months[0],
            "coverage_end": months[-1],
            "source_statement": (
                "Metadata from SAP Security Patch Day publications "
                "(support.sap.com, public, no login required); "
                "exploitation data from CISA KEV"
            ),
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
        raise SystemExit(f"{len(errors)} schema violation(s) — catalog NOT written")

    CATALOG_PATH.write_text(json.dumps(catalog, indent=1) + "\n")
    write_discrepancy_report(discrepancies, coverage)

    print(f"\nWrote {CATALOG_PATH}: {len(records)} notes, "
          f"{months[0]} -> {months[-1]}, {kev_count} KEV-listed")
    print(f"Discrepancies: {len(discrepancies)} "
          f"(added={sum(1 for d in discrepancies if d['kind']=='added_from_pages')}, "
          f"missing={sum(1 for d in discrepancies if d['kind']=='missing_from_pages')}, "
          f"changed={sum(1 for d in discrepancies if d['kind']=='field_changed')})")


if __name__ == "__main__":
    main()

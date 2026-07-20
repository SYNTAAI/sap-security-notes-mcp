"""Build the notes catalog from public SAP Security Patch Day pages
(canonical source as of v2.1) plus the CISA KEV feed.

Always rebuilds fresh from ALL cached pages (data/pages/YYYY-MM.html) each
time — there is no incremental hand-patched state. This keeps "the pages
are the source of truth" literal: adding a new month means caching one
more page and rebuilding, never editing notes_catalog.json by hand.

Merge semantics across months (chronological order matters):
- A note_number's CANONICAL record comes from its LATEST page appearance
  (by month) — SAP's most recently published data wins on any conflict.
- is_update = the note was ever seen in more than one distinct month, or
  the latest appearance carries an "Update to Security Note released on
  <Month> <Year> Patch Day" hint naming an earlier origin month.
- released_on day ships only when publicly evidenced: the row is in the
  main patch-day table (table_index 0, section 'new') of its month, so the
  day equals that page's stated patch-day date, OR the day is in the
  manually-verified NVD_CONFIRMED_DATES allowlist. Otherwise null, with
  release_month always retained.
- `component` (the legacy SAP *application* component, e.g. BC-MID-RFC)
  is a different taxonomy than what pages publish (software component /
  product). It is preserved from the prior xlsx-derived catalog when
  available, and left null — never fabricated — for notes discovered only
  on pages. Those notes remain reachable via the affected[] software
  component / product taxonomy (see catalog.py's version-aware exposure).
"""

import re
from datetime import datetime
from pathlib import Path

from parse_patchday_page import (
    MONTH_NAMES, parse_page, parse_patch_day_date,
)

# Manually verified against the public NVD API (see reports/ and the
# 2026-07-20 spot audit) — the only off-patch-day days shippable as public.
NVD_CONFIRMED_DATES = {
    "3433366": "2026-05-26",
    "3646297": "2026-02-24",
    "3122486": "2026-01-27",
}

CVSS_VECTOR_RE = re.compile(r"^CVSS:\d+\.\d+/AV:")


def _is_patch_day_shaped(iso: str) -> bool:
    d = datetime.strptime(iso, "%Y-%m-%d").date()
    return d.weekday() == 1 and 8 <= d.day <= 14


def public_date(note_number: str, iso: str | None) -> str | None:
    if not iso:
        return None
    if _is_patch_day_shaped(iso) or NVD_CONFIRMED_DATES.get(note_number) == iso:
        return iso
    return None


def normalize_priority(raw: str) -> str:
    lowered = (raw or "").strip().lower()
    if "critical" in lowered or "hotnews" in lowered or "hot news" in lowered:
        return "HotNews"
    if "high" in lowered:
        return "High"
    if "medium" in lowered:
        return "Medium"
    if "low" in lowered:
        return "Low"
    raise ValueError(f"Unrecognized priority string: {raw!r}")


def _hint_to_month(hint: str | None) -> str | None:
    """'January 2026' -> '2026-01'."""
    if not hint:
        return None
    m = re.match(r"([A-Za-z]+)\s+(\d{4})", hint.strip())
    if not m:
        return None
    name, year = m.group(1).lower(), m.group(2)
    if name not in MONTH_NAMES:
        return None
    return f"{year}-{MONTH_NAMES.index(name) + 1:02d}"


def load_cached_pages(pages_dir: Path) -> dict[str, tuple[str, str]]:
    """month -> (html, source_url), reading data/pages/YYYY-MM.html and the
    canonical support.sap.com URL for that month."""
    pages = {}
    for path in sorted(pages_dir.glob("????-??.html")):
        month = path.stem
        year, mm = month.split("-")
        name = MONTH_NAMES[int(mm) - 1]
        url = (
            "https://support.sap.com/en/my-support/knowledge-base/"
            f"security-notes-news/{name}-{year}.html"
        )
        pages[month] = (path.read_text(errors="ignore"), url)
    return pages


def build_catalog_from_pages(
    pages: dict[str, tuple[str, str]],
    kev_by_cve: dict,
    old_notes_by_number: dict[str, dict] | None = None,
) -> tuple[dict[str, dict], list[dict], dict]:
    """Returns (notes_by_number, discrepancies, parse_coverage_by_month)."""
    old_notes_by_number = old_notes_by_number or {}
    months = sorted(pages)

    all_rows: list[dict] = []
    coverage: dict[str, dict] = {}
    patch_day_of: dict[str, str | None] = {}
    for month in months:
        page_html, source_url = pages[month]
        rows = parse_page(page_html, source_url, month)
        all_rows.extend(rows)
        patch_day_of[month] = parse_patch_day_date(page_html)
        total = len(rows)
        unparsed = [r["note_number"] for r in rows
                    if r["versions_unparsed"] is not None]
        coverage[month] = {
            "total": total, "parsed": total - len(unparsed),
            "unparsed": len(unparsed), "unparsed_notes": unparsed,
        }

    notes: dict[str, dict] = {}
    first_seen_month: dict[str, str] = {}
    seen_months: dict[str, set] = {}
    source_urls: dict[str, set] = {}
    ever_updated: dict[str, bool] = {}
    discrepancies: list[dict] = []

    for rec in all_rows:
        num = rec["note_number"]
        month = rec["month"]
        first_seen_month.setdefault(num, month)
        seen_months.setdefault(num, set()).add(month)
        source_urls.setdefault(num, set()).add(rec["source_url"])
        if rec["section"] == "updated":
            ever_updated[num] = True

        cve_ids = rec["cve_ids"]
        kev_hits = [kev_by_cve[c] for c in cve_ids if c in kev_by_cve]
        kev_listed = bool(kev_hits)
        kev_date_added = min(h.get("dateAdded") for h in kev_hits) if kev_hits else None

        cvss_score = rec["cvss_score"]
        vector = rec.get("cvss_vector")

        candidate_day = None
        if rec["section"] == "new" and rec.get("table_index") == 0:
            candidate_day = patch_day_of.get(month)
        released_on = public_date(num, candidate_day)

        old = old_notes_by_number.get(num)
        component = old["component"] if old else None

        final_vector = vector if vector else (old["cvss_vector"] if old else None)
        canonical = {
            "note_number": num,
            "title": rec["title"],
            "cve_ids": cve_ids,
            "cvss_score": cvss_score,
            "cvss_vector": final_vector,
            "priority": normalize_priority(rec["priority_raw"]),
            "priority_raw": rec["priority_raw"],
            "category": old["category"] if old else None,
            "component": component,
            "release_month": month,
            "released_on": released_on,
            "note_url": rec["note_url"],
            "product_names": rec["product_names"],
            "affected": rec["affected"],
            "versions_unparsed": rec["versions_unparsed"],
            "kev_listed": kev_listed,
            "kev_date_added": kev_date_added,
        }
        if final_vector and not CVSS_VECTOR_RE.match(final_vector):
            canonical["cvss_vector_malformed"] = True
        if rec["multiple_cves"]:
            canonical["multiple_cves"] = True
        if rec["section"] == "updated":
            canonical["_update_hint_month"] = _hint_to_month(rec["update_hint_month"])

        prev = notes.get(num)
        if prev and month < prev["release_month"]:
            # Should not happen since months are processed in order, but
            # never let an earlier row overwrite a later canonical record.
            continue
        notes[num] = canonical

    for num, canonical in notes.items():
        origin_candidates = [first_seen_month[num]]
        hint_month = canonical.pop("_update_hint_month", None)
        if hint_month:
            origin_candidates.append(hint_month)
        origin_month = min(origin_candidates)
        is_update = (
            ever_updated.get(num, False)
            or len(seen_months[num]) > 1
            or origin_month != canonical["release_month"]
        )
        canonical["is_update"] = is_update
        if is_update:
            first_day = None
            if origin_month in patch_day_of:
                first_row = next(
                    (r for r in all_rows
                     if r["note_number"] == num and r["month"] == origin_month
                     and r["section"] == "new" and r.get("table_index") == 0),
                    None,
                )
                if first_row:
                    first_day = public_date(num, patch_day_of[origin_month])
            canonical["first_released_on"] = first_day
        else:
            canonical["first_released_on"] = canonical["released_on"]
        canonical["source_urls"] = sorted(source_urls[num])

        old = old_notes_by_number.get(num)
        if old is None:
            discrepancies.append({
                "note_number": num, "kind": "added_from_pages",
                "detail": f"On public page(s) {canonical['source_urls']} "
                          "but absent from the prior xlsx-derived catalog.",
            })
        else:
            for field in ("title", "priority", "cvss_score", "cve_ids",
                          "release_month"):
                if old.get(field) != canonical.get(field):
                    discrepancies.append({
                        "note_number": num, "kind": "field_changed",
                        "field": field,
                        "old_value": old.get(field),
                        "new_value": canonical.get(field),
                    })

    for num, old in old_notes_by_number.items():
        if num not in notes:
            discrepancies.append({
                "note_number": num, "kind": "missing_from_pages",
                "detail": "In the prior catalog but not found on any of "
                          "the fetched public pages — kept, needs human "
                          "review.",
            })
            kept = dict(old)
            kept.setdefault("product_names", [])
            kept.setdefault("affected", [])
            kept.setdefault("versions_unparsed", None)
            kept.setdefault("source_urls", [])
            notes[num] = kept

    return notes, discrepancies, coverage

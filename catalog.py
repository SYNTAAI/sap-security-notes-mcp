"""Load, index and query the SAP Security Notes metadata catalog.

All query logic lives here so it can be unit-tested without an MCP runtime.
server.py exposes thin tool wrappers around these functions.

Honesty rules enforced here:
- Absence from the catalog NEVER implies absence of vulnerability; every
  not-found path returns an explicit message saying so.
- Nothing is fabricated: answers come only from data/notes_catalog.json.
"""

import json
import os
from pathlib import Path

NULL_EVIDENCE = (
    "Absence from this catalog does not mean absence of vulnerability. "
    "This catalog covers SAP Security Note metadata for a fixed window only "
    "(see get_catalog_info). Always review the full SAP note via your SAP "
    "support access before acting."
)

VERSION_CAVEAT = (
    "Version applicability not assessed — matching is component-level only. "
    "Confirm affected versions against the full SAP note."
)

DEFAULT_CATALOG_PATH = Path(__file__).parent / "data" / "notes_catalog.json"


class Catalog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(
            path or os.getenv("NOTES_CATALOG_PATH", DEFAULT_CATALOG_PATH)
        )
        raw = json.loads(self.path.read_text())
        self.meta: dict = raw["catalog_meta"]
        self.notes: list[dict] = raw["notes"]

        self.by_number: dict[str, dict] = {}
        self.by_cve: dict[str, list[dict]] = {}
        self.by_component: dict[str, list[dict]] = {}
        self.by_month: dict[str, list[dict]] = {}
        for note in self.notes:
            self.by_number[note["note_number"]] = note
            for cve in note["cve_ids"]:
                self.by_cve.setdefault(cve.upper(), []).append(note)
            self.by_component.setdefault(note["component"].upper(), []).append(note)
            self.by_month.setdefault(note["release_month"], []).append(note)

    # ------------------------------------------------------------------ helpers

    @property
    def months(self) -> list[str]:
        return sorted(self.by_month)

    @property
    def latest_month(self) -> str:
        return self.months[-1]

    @staticmethod
    def _since_date(since: str | None) -> str | None:
        """Accept '2026-03' or '2026-03-01'; return a comparable ISO date."""
        if not since:
            return None
        since = since.strip()
        if len(since) == 7:  # YYYY-MM
            return since + "-01"
        return since[:10]

    def _filter_since(self, notes: list[dict], since: str | None) -> list[dict]:
        cutoff = self._since_date(since)
        if not cutoff:
            return notes
        return [n for n in notes if n["released_on"] >= cutoff]

    @staticmethod
    def _sort_by_cvss(notes: list[dict]) -> list[dict]:
        return sorted(
            notes,
            key=lambda n: (n["cvss_score"] is not None, n["cvss_score"] or 0),
            reverse=True,
        )

    @staticmethod
    def _brief(note: dict) -> dict:
        return {
            "note_number": note["note_number"],
            "title": note["title"],
            "component": note["component"],
            "priority": note["priority"],
            "cvss_score": note["cvss_score"],
            "cve_ids": note["cve_ids"],
            "released_on": note["released_on"],
            "kev_listed": note["kev_listed"],
            "note_url": note["note_url"],
        }

    def _component_matches(self, component: str) -> tuple[list[dict], str]:
        """Exact match plus prefix match (BC-JAS matches BC-JAS-WEB).

        Returns (notes, match_mode) with match_mode one of
        'exact', 'prefix', 'exact+prefix', 'none'.
        """
        key = component.strip().upper()
        exact = list(self.by_component.get(key, []))
        prefix = [
            n
            for comp, notes in self.by_component.items()
            if comp != key and comp.startswith(key + "-")
            for n in notes
        ]
        if exact and prefix:
            mode = "exact+prefix"
        elif exact:
            mode = "exact"
        elif prefix:
            mode = "prefix"
        else:
            mode = "none"
        return exact + prefix, mode

    # ------------------------------------------------------------------ queries

    def catalog_info(self) -> dict:
        return {
            "catalog_meta": self.meta,
            "months_covered": self.months,
            "null_evidence_rule": NULL_EVIDENCE,
        }

    def patch_day_summary(self, month: str | None = None) -> dict:
        month = (month or self.latest_month).strip()
        notes = self.by_month.get(month)
        if not notes:
            return {
                "month": month,
                "found": False,
                "message": (
                    f"No notes for {month} in this catalog "
                    f"(covered months: {', '.join(self.months)}). " + NULL_EVIDENCE
                ),
            }
        by_priority = {}
        by_component: dict[str, int] = {}
        for n in notes:
            by_priority[n["priority"]] = by_priority.get(n["priority"], 0) + 1
            by_component[n["component"]] = by_component.get(n["component"], 0) + 1
        top_components = sorted(
            by_component.items(), key=lambda kv: (-kv[1], kv[0])
        )[:5]
        return {
            "month": month,
            "found": True,
            "total_notes": len(notes),
            "counts_by_priority": by_priority,
            "hot_news": [self._brief(n) for n in self._sort_by_cvss(notes)
                         if n["priority"] == "HotNews"],
            "top_components": [
                {"component": c, "note_count": k} for c, k in top_components
            ],
            "new_notes": sum(1 for n in notes if not n["is_update"]),
            "updated_notes": sum(1 for n in notes if n["is_update"]),
            "kev_listed": [self._brief(n) for n in notes if n["kev_listed"]],
            "note": NULL_EVIDENCE,
        }

    def search(
        self,
        query: str,
        component: str | None = None,
        priority: str | None = None,
        min_cvss: float | None = None,
        month: str | None = None,
    ) -> dict:
        terms = [t for t in query.lower().split() if t]
        results = []
        for n in self.notes:
            haystack = f"{n['title']} {n['component']}".lower()
            if terms and not all(t in haystack for t in terms):
                continue
            if component and not n["component"].upper().startswith(
                component.strip().upper()
            ):
                continue
            if priority and n["priority"].lower() != priority.strip().lower():
                continue
            if min_cvss is not None and (
                n["cvss_score"] is None or n["cvss_score"] < min_cvss
            ):
                continue
            if month and n["release_month"] != month.strip():
                continue
            results.append(n)
        results = self._sort_by_cvss(results)
        return {
            "query": query,
            "result_count": len(results),
            "results": [self._brief(n) for n in results],
            "note": NULL_EVIDENCE,
        }

    def note_details(self, note_number: str) -> dict:
        key = str(note_number).strip()
        note = self.by_number.get(key)
        if not note:
            return {
                "note_number": key,
                "found": False,
                "message": (
                    f"SAP note {key} is not in this catalog. " + NULL_EVIDENCE
                ),
            }
        return {"found": True, "note": note}

    def notes_by_component(self, component: str, since: str | None = None) -> dict:
        matches, mode = self._component_matches(component)
        matches = self._filter_since(matches, since)
        if not matches:
            return {
                "component": component,
                "match_mode": "none",
                "found": False,
                "message": (
                    f"No notes in this catalog for component '{component}'"
                    + (f" since {since}" if since else "")
                    + ". " + NULL_EVIDENCE
                ),
            }
        return {
            "component": component,
            "match_mode": mode,
            "found": True,
            "result_count": len(matches),
            "results": [self._brief(n) for n in self._sort_by_cvss(matches)],
            "version_caveat": VERSION_CAVEAT,
            "note": NULL_EVIDENCE,
        }

    def hot_news(self, since: str | None = None) -> dict:
        notes = self._filter_since(
            [n for n in self.notes if n["priority"] == "HotNews"], since
        )
        return {
            "result_count": len(notes),
            "results": [self._brief(n) for n in self._sort_by_cvss(notes)],
            "note": NULL_EVIDENCE,
        }

    def lookup_cve(self, cve_id: str) -> dict:
        key = cve_id.strip().upper()
        notes = self.by_cve.get(key, [])
        if not notes:
            return {
                "cve_id": key,
                "found": False,
                "message": (
                    f"{key} is not associated with any SAP note in this "
                    "catalog. Notes tagged '[Multiple CVEs]' do not list "
                    "individual CVE IDs in the source metadata, so this CVE "
                    "could still be covered by one of those notes. "
                    + NULL_EVIDENCE
                ),
            }
        return {
            "cve_id": key,
            "found": True,
            "results": [self._brief(n) for n in notes],
            "note": NULL_EVIDENCE,
        }

    def component_exposure(
        self, components: list[str], since: str | None = None
    ) -> dict:
        matched, unmatched = [], []
        for comp in components:
            comp = str(comp).strip()
            if not comp:
                continue
            hits, mode = self._component_matches(comp)
            hits = self._filter_since(hits, since)
            if hits:
                matched.append({
                    "component": comp,
                    "match_mode": mode,
                    "result_count": len(hits),
                    "notes": [self._brief(n) for n in self._sort_by_cvss(hits)],
                })
            else:
                unmatched.append(comp)
        return {
            "matched": matched,
            "no_notes_in_catalog": {
                "components": unmatched,
                "message": (
                    "No notes in this catalog for these components — this "
                    "does not mean no vulnerabilities exist for them."
                ),
            },
            "version_caveat": VERSION_CAVEAT,
            "note": NULL_EVIDENCE,
        }

    def exploited_notes(self, since: str | None = None) -> dict:
        notes = self._filter_since(
            [n for n in self.notes if n["kev_listed"]], since
        )
        return {
            "result_count": len(notes),
            "results": [
                {**self._brief(n), "kev_date_added": n["kev_date_added"]}
                for n in self._sort_by_cvss(notes)
            ],
            "kev_snapshot_version": self.meta.get("kev_snapshot_version"),
            "kev_snapshot_fetched": self.meta.get("kev_snapshot_fetched"),
            "message": (
                "Exploitation status is from the CISA KEV catalog snapshot "
                "above. A count of zero means none of the catalog's CVEs "
                "were KEV-listed at snapshot time — not that exploitation "
                "is impossible. " + NULL_EVIDENCE
            ),
        }

    def compare_months(self, month_a: str, month_b: str) -> dict:
        month_a, month_b = month_a.strip(), month_b.strip()
        missing = [m for m in (month_a, month_b) if m not in self.by_month]
        if missing:
            return {
                "found": False,
                "message": (
                    f"Month(s) not in catalog: {', '.join(missing)} "
                    f"(covered: {', '.join(self.months)}). " + NULL_EVIDENCE
                ),
            }

        def stats(month: str) -> dict:
            notes = self.by_month[month]
            scores = [n["cvss_score"] for n in notes if n["cvss_score"] is not None]
            return {
                "month": month,
                "total_notes": len(notes),
                "counts_by_priority": {
                    p: sum(1 for n in notes if n["priority"] == p)
                    for p in ("HotNews", "High", "Medium", "Low")
                },
                "max_cvss": max(scores) if scores else None,
                "avg_cvss": round(sum(scores) / len(scores), 2) if scores else None,
                "hot_news_notes": [
                    self._brief(n) for n in notes if n["priority"] == "HotNews"
                ],
            }

        a, b = stats(month_a), stats(month_b)
        return {
            "found": True,
            "month_a": a,
            "month_b": b,
            "delta": {
                "total_notes": b["total_notes"] - a["total_notes"],
                "hot_news": (
                    b["counts_by_priority"]["HotNews"]
                    - a["counts_by_priority"]["HotNews"]
                ),
            },
            "note": NULL_EVIDENCE,
        }

    def distinct_components(self) -> list[str]:
        return sorted({n["component"] for n in self.notes})

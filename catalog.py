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
import re
from pathlib import Path

try:
    import yaml
except ImportError:  # mapping features degrade gracefully without PyYAML
    yaml = None

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
DEFAULT_MAPPING_PATH = Path(__file__).parent / "data" / "component_mapping.yaml"

# SAP application components look like BC-MID-RFC / CA-FLP-FE-COR
APP_COMPONENT_RE = re.compile(r"^[A-Z]{2,3}(-[A-Z0-9]+)+$")
# Software components look like SAP_BASIS / S4CORE / UIS4HOP1 (no hyphen)
SOFTWARE_COMPONENT_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
RELEASE_YEAR_RE = re.compile(r"\b(?:19|20)\d{2}\b")


def _covers(component: str, prefix: str) -> bool:
    """Prefix semantics used by the mapping: equal, or a '-' boundary."""
    return component == prefix or component.startswith(prefix + "-")


class Catalog:
    def __init__(
        self,
        path: str | Path | None = None,
        mapping_path: str | Path | None = None,
    ):
        self.path = Path(
            path or os.getenv("NOTES_CATALOG_PATH", DEFAULT_CATALOG_PATH)
        )
        raw = json.loads(self.path.read_text())
        self.meta: dict = raw["catalog_meta"]
        self.notes: list[dict] = raw["notes"]

        self.mapping: dict | None = None
        mp = Path(
            mapping_path
            or os.getenv("NOTES_COMPONENT_MAPPING_PATH", DEFAULT_MAPPING_PATH)
        )
        if yaml is not None and mp.exists():
            self.mapping = yaml.safe_load(mp.read_text())

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

    # ----------------------------------------------------- taxonomy (v1.1/v2)

    TAXONOMY_NOTE = (
        "This catalog is indexed by SAP application component (e.g. "
        "BC-MID-RFC) — the component shown in each SAP note's header. "
        "Software components (System → Status, e.g. SAP_BASIS) and product "
        "names (Maintenance Planner, e.g. 'SAP S/4HANA 2023') are different "
        "taxonomies and are resolved via a curated mapping where one exists."
    )

    def classify_component_input(self, item: str) -> dict:
        """Classify one pasted item: application_component, software_component,
        product, or unknown."""
        text = str(item).strip()
        up = re.sub(r"\s+", " ", text.upper())
        sw = (self.mapping or {}).get("software_components", {})

        if up in sw:
            return {"input": text, "type": "software_component", "key": up,
                    "mapped": True}

        if up in self.by_component or APP_COMPONENT_RE.match(up):
            return {"input": text, "type": "application_component", "key": up}

        product = self._match_product(up)
        if product:
            return {
                "input": text, "type": "product", "key": product,
                "mapped": True,
                "releases": RELEASE_YEAR_RE.findall(up),
            }

        if SOFTWARE_COMPONENT_RE.match(up):
            return {"input": text, "type": "software_component", "key": up,
                    "mapped": False}

        if " " in up:
            return {"input": text, "type": "product", "key": None,
                    "mapped": False,
                    "releases": RELEASE_YEAR_RE.findall(up)}

        return {"input": text, "type": "unknown", "key": None}

    def _match_product(self, up: str) -> str | None:
        """Match input text against product aliases. When several products
        match (e.g. 'SAP FIORI FES FOR S/4HANA'), the alias appearing
        earliest in the string wins."""
        best = None  # (position, -alias_len, product_key)
        for key, entry in (self.mapping or {}).get("products", {}).items():
            for alias in [key] + list(entry.get("aliases", [])):
                pos = up.find(alias.upper())
                if pos >= 0:
                    cand = (pos, -len(alias), key)
                    if best is None or cand < best:
                        best = cand
        return best[2] if best else None

    def _resolve_software_component(
        self, sw_key: str, since: str | None
    ) -> tuple[list[dict], list[str]]:
        """Return (notes, effective_prefixes) for a mapped software component,
        honoring excluded_prefixes."""
        entry = self.mapping["software_components"][sw_key]
        prefixes = entry.get("app_component_prefixes") or []
        excluded = entry.get("excluded_prefixes") or []
        hits = [
            n for n in self.notes
            if any(_covers(n["component"], p) for p in prefixes)
            and not any(_covers(n["component"], x) for x in excluded)
        ]
        return self._filter_since(hits, since), prefixes

    @staticmethod
    def _dedup(notes: list[dict]) -> list[dict]:
        seen, out = set(), []
        for n in notes:
            if n["note_number"] not in seen:
                seen.add(n["note_number"])
                out.append(n)
        return out

    def component_exposure(
        self, components: list[str], since: str | None = None
    ) -> dict:
        matched, not_assessed, releases_noted = [], [], []
        sw_map = (self.mapping or {}).get("software_components", {})
        guidance_tail = (
            " This does not mean no vulnerabilities exist for it. "
            + self.TAXONOMY_NOTE
        )

        for raw_item in components:
            item = str(raw_item).strip()
            if not item:
                continue
            cls = self.classify_component_input(item)
            kind = cls["type"]

            if kind == "application_component":
                hits, mode = self._component_matches(cls["key"])
                hits = self._filter_since(hits, since)
                if hits:
                    exact = {n["note_number"]
                             for n in self.by_component.get(cls["key"], [])}
                    matched.append({
                        "input": item,
                        "classification": "application_component",
                        "match_mode": mode,
                        "provenance": (
                            f"Matched directly on application component "
                            f"'{cls['key']}' ({mode} match)."
                        ),
                        "result_count": len(hits),
                        "notes": [
                            {**self._brief(n),
                             "match_type": "direct"
                             if n["note_number"] in exact else "prefix"}
                            for n in self._sort_by_cvss(hits)
                        ],
                    })
                else:
                    not_assessed.append({
                        "input": item,
                        "classification": "application_component",
                        "reason": (
                            f"'{cls['key']}' is an application component but "
                            "has no notes in this catalog."
                            + " This does not mean no vulnerabilities exist "
                            "for it."
                        ),
                    })

            elif kind == "software_component" and cls["mapped"]:
                hits, prefixes = self._resolve_software_component(
                    cls["key"], since
                )
                explanation = (
                    f"'{item}' is a software component; this catalog is "
                    "indexed by application component. Resolved via curated "
                    "mapping."
                )
                if not prefixes:
                    not_assessed.append({
                        "input": item,
                        "classification": "software_component",
                        "reason": (
                            f"'{cls['key']}' is a known software component, "
                            "but no application-component prefixes are "
                            "curated for it yet — not assessed."
                            + guidance_tail
                        ),
                    })
                elif hits:
                    prefix_desc = ", ".join(f"{p}-*" for p in prefixes)
                    matched.append({
                        "input": item,
                        "classification": "software_component",
                        "explanation": explanation,
                        "resolved_via": f"{cls['key']} → {prefix_desc}",
                        "provenance": (
                            f"Matched via curated mapping ({cls['key']} → "
                            f"{prefix_desc}) — mapping-derived, confirm "
                            "applicability against the full SAP note."
                        ),
                        "result_count": len(hits),
                        "notes": [
                            {**self._brief(n),
                             "match_type": "mapped_software_component"}
                            for n in self._sort_by_cvss(hits)
                        ],
                    })
                else:
                    not_assessed.append({
                        "input": item,
                        "classification": "software_component",
                        "reason": (
                            f"'{cls['key']}' resolved via curated mapping, "
                            "but no notes in this catalog match its "
                            "application-component prefixes"
                            + (f" since {since}" if since else "")
                            + "." + guidance_tail
                        ),
                    })

            elif kind == "software_component":
                not_assessed.append({
                    "input": item,
                    "classification": "software_component",
                    "reason": (
                        f"'{cls['key']}' looks like a software component; "
                        "this catalog is indexed by application component "
                        "and no curated mapping exists for it yet — could "
                        "not map, not assessed." + guidance_tail
                    ),
                })

            elif kind == "product" and cls["mapped"]:
                product = cls["key"]
                entry = self.mapping["products"][product]
                if cls.get("releases"):
                    releases_noted.append(
                        f"your stack: {product} {'/'.join(cls['releases'])} "
                        "— release echoed only; version applicability is "
                        "not assessed"
                    )
                all_hits, chain_parts = [], []
                for sw_key in entry.get("software_components", []):
                    if sw_key not in sw_map:
                        continue
                    hits, prefixes = self._resolve_software_component(
                        sw_key, since
                    )
                    if prefixes:
                        chain_parts.append(
                            f"{sw_key} → "
                            + ", ".join(f"{p}-*" for p in prefixes)
                        )
                    else:
                        chain_parts.append(f"{sw_key} → (no prefixes curated)")
                    all_hits.extend(hits)
                all_hits = self._dedup(all_hits)
                chain = (
                    f"{product}"
                    + (f" (release {'/'.join(cls['releases'])} echoed only)"
                       if cls.get("releases") else "")
                    + " → software components "
                    + ", ".join(entry.get("software_components", []))
                    + " → " + "; ".join(chain_parts)
                )
                if all_hits:
                    matched.append({
                        "input": item,
                        "classification": "product",
                        "explanation": (
                            f"'{item}' is a product/stack name; resolved "
                            "product → software components → application-"
                            "component prefixes via curated mapping."
                        ),
                        "resolved_via": chain,
                        "provenance": (
                            f"Matched via curated mapping ({chain}) — "
                            "mapping-derived, confirm applicability against "
                            "the full SAP note."
                        ),
                        "result_count": len(all_hits),
                        "notes": [
                            {**self._brief(n), "match_type": "mapped_product"}
                            for n in self._sort_by_cvss(all_hits)
                        ],
                    })
                else:
                    not_assessed.append({
                        "input": item,
                        "classification": "product",
                        "reason": (
                            f"'{item}' resolved via curated mapping "
                            f"({chain}), but no catalog notes matched."
                            + guidance_tail
                        ),
                    })

            elif kind == "product":
                not_assessed.append({
                    "input": item,
                    "classification": "product",
                    "reason": (
                        f"'{item}' looks like a product/stack name, but no "
                        "curated product mapping matched — could not map, "
                        "not assessed." + guidance_tail
                    ),
                })

            else:
                not_assessed.append({
                    "input": item,
                    "classification": "unknown",
                    "reason": (
                        f"Could not classify '{item}' as an application "
                        "component, software component, or product — could "
                        "not map, not assessed." + guidance_tail
                    ),
                })

        result = {
            "taxonomy_note": self.TAXONOMY_NOTE,
            "matched": matched,
            "could_not_map_or_no_match": {
                "items": not_assessed,
                "message": (
                    "Items here were not assessed (no catalog match, or no "
                    "curated mapping). No bucket in this response ever "
                    "implies safety: absence from this catalog does not "
                    "mean absence of vulnerability."
                ),
            },
            "version_caveat": VERSION_CAVEAT,
            "note": NULL_EVIDENCE,
        }
        if releases_noted:
            result["releases_noted"] = releases_noted
        if self.mapping is None:
            result["mapping_status"] = (
                "component_mapping.yaml not loaded — software-component and "
                "product inputs were classified but not resolved."
            )
        return result

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

#!/usr/bin/env python3
"""v2.1 mapping validation: cross-check data/component_mapping.yaml's
curated app-component -> software-component inferences against what SAP
actually publishes (data/notes_catalog.json's affected[] field).

For each curated software_component entry with app_component_prefixes:
  - CONFIRMED: a note the mapping predicts also publishes that exact
    software component in its affected[] list.
  - CONTRADICTED: a note the mapping predicts DOES publish affected[] data,
    but that data does NOT include this software component (i.e. the page
    itself disagrees with our inference for THIS note).
  - NO EVIDENCE: notes the mapping predicts where the page has no parsed
    affected[] data at all (versions_unparsed, or genuinely no version
    line) -- neither confirms nor contradicts.

Writes reports/v21_mapping_validation.md. Does NOT edit the YAML -- this
is a report for human sign-off, same gate as the original v2 mapping.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from catalog import Catalog, _covers  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO_ROOT / "reports"


def main() -> None:
    cat = Catalog()
    if cat.mapping is None:
        raise SystemExit("component_mapping.yaml not found/loadable")

    lines = [
        "# v2.1 Mapping Validation Report",
        "",
        "Cross-checks `data/component_mapping.yaml`'s curated "
        "app-component -> software-component inferences against what SAP "
        "actually publishes in each note's `affected[]` list. "
        "**This report does not edit the YAML** -- changes wait for "
        "human sign-off, same gate as the original v2 mapping.",
        "",
    ]

    total_confirmed = total_contradicted = total_no_evidence = 0

    for sw_key, entry in sorted(cat.mapping["software_components"].items()):
        prefixes = entry.get("app_component_prefixes") or []
        excluded = entry.get("excluded_prefixes") or []
        if not prefixes:
            continue

        predicted = [
            n for n in cat.notes
            if n.get("component")
            and any(_covers(n["component"], p) for p in prefixes)
            and not any(_covers(n["component"], x) for x in excluded)
        ]
        if not predicted:
            continue

        confirmed, contradicted, no_evidence = [], [], []
        for n in predicted:
            aff_keys = {a["software_component"].upper()
                       for a in n.get("affected") or []}
            if sw_key.upper() in aff_keys:
                confirmed.append(n)
            elif n.get("affected") or n.get("versions_unparsed"):
                # The page DID publish some component/version data for
                # this note, and it does NOT include sw_key -> contradiction.
                if n.get("affected"):
                    contradicted.append(n)
                else:
                    no_evidence.append(n)  # unparsed text, can't judge
            else:
                no_evidence.append(n)

        total_confirmed += len(confirmed)
        total_contradicted += len(contradicted)
        total_no_evidence += len(no_evidence)

        lines += [
            f"## {sw_key}",
            "",
            f"Curated prefixes: `{', '.join(prefixes)}` "
            f"(excluded: `{', '.join(excluded) or '-'}`)",
            "",
            f"- Confirmed: {len(confirmed)}",
            f"- Contradicted: {len(contradicted)}",
            f"- No page evidence: {len(no_evidence)}",
            "",
        ]
        if confirmed:
            lines.append("**Confirmed** (mapping agrees with published data):")
            for n in confirmed:
                lines.append(f"- {n['note_number']} ({n['component']})")
            lines.append("")
        if contradicted:
            lines.append(
                "**Contradicted** (published affected[] does NOT include "
                f"{sw_key} for this note -- review):"
            )
            for n in contradicted:
                aff = ", ".join(a["software_component"]
                                for a in n["affected"])
                lines.append(
                    f"- {n['note_number']} ({n['component']}) -- "
                    f"published: {aff}"
                )
            lines.append("")
        if no_evidence:
            lines.append("**No page evidence either way:**")
            for n in no_evidence:
                lines.append(f"- {n['note_number']} ({n['component']})")
            lines.append("")

    # Mapping entries with zero supporting evidence at all (curated but
    # either no notes predicted, or predicted notes are ALL no-evidence).
    lines += ["## Mapping entries with zero page evidence", ""]
    zero_evidence_entries = []
    for sw_key, entry in sorted(cat.mapping["software_components"].items()):
        prefixes = entry.get("app_component_prefixes") or []
        if not prefixes:
            continue
        predicted = [
            n for n in cat.notes
            if n.get("component")
            and any(_covers(n["component"], p) for p in prefixes)
            and not any(_covers(n["component"], x)
                       for x in entry.get("excluded_prefixes") or [])
        ]
        has_any_confirmation = any(
            sw_key.upper() in {a["software_component"].upper()
                               for a in n.get("affected") or []}
            for n in predicted
        )
        if predicted and not has_any_confirmation:
            zero_evidence_entries.append(sw_key)
    if zero_evidence_entries:
        for k in zero_evidence_entries:
            lines.append(f"- **{k}** -- predicted notes exist but none "
                         "publish this exact software component name")
    else:
        lines.append("None -- every curated entry with predictions has at "
                     "least one confirming note.")

    lines += [
        "",
        "## Summary",
        "",
        f"- Total confirmed: {total_confirmed}",
        f"- Total contradicted: {total_contradicted}",
        f"- Total no page evidence: {total_no_evidence}",
    ]

    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "v21_mapping_validation.md").write_text(
        "\n".join(lines) + "\n"
    )
    print(f"confirmed={total_confirmed} contradicted={total_contradicted} "
          f"no_evidence={total_no_evidence}")
    print(f"zero-evidence mapping entries: {zero_evidence_entries}")


if __name__ == "__main__":
    main()

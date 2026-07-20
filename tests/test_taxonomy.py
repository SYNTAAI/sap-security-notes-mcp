"""v1.1/v2 taxonomy tests: input classification, curated-mapping integrity,
provenance labeling, and the end-to-end stack paste.

Mapping-dependent tests are skipped if data/component_mapping.yaml is absent
(the mechanism degrades gracefully without it), but in CI the file is present
and everything runs.
"""

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
MAPPING = REPO / "data" / "component_mapping.yaml"

needs_mapping = pytest.mark.skipif(
    not MAPPING.exists(), reason="component_mapping.yaml not present"
)


# ------------------------------------------------------------ classification

def test_classify_application_component(real_cat):
    c = real_cat.classify_component_input("BC-JAS-WEB")
    assert c["type"] == "application_component"
    # 'ICM' has no hyphen but exists in the catalog index
    assert real_cat.classify_component_input("ICM")["type"] == (
        "application_component"
    )


@needs_mapping
def test_classify_software_component(real_cat):
    c = real_cat.classify_component_input("SAP_BASIS")
    assert c["type"] == "software_component" and c["mapped"] is True
    # ST-PI looks like an app component pattern but is a known software
    # component — the mapping key must win
    c = real_cat.classify_component_input("ST-PI")
    assert c["type"] == "software_component" and c["mapped"] is True


def test_classify_unknown_software_component(real_cat):
    c = real_cat.classify_component_input("SAP_HRRXX")
    assert c["type"] == "software_component"
    assert c["mapped"] is False


@needs_mapping
def test_classify_product_and_release(real_cat):
    c = real_cat.classify_component_input("S4HANA ON PREMISE 2023")
    assert c["type"] == "product" and c["key"] == "SAP S/4HANA"
    assert c["releases"] == ["2023"]
    c = real_cat.classify_component_input("SAP FIORI FES FOR S/4HANA")
    # earliest alias in the string wins: FIORI before S/4HANA
    assert c["key"] == "SAP FIORI"


def test_classify_mixed_list(real_cat):
    kinds = {
        i: real_cat.classify_component_input(i)["type"]
        for i in ["BC-JAS-WEB", "SAP_BASIS", "SAP S/4HANA 2023", "???"]
    }
    assert kinds["BC-JAS-WEB"] == "application_component"
    assert kinds["SAP_BASIS"] == "software_component"
    assert kinds["SAP S/4HANA 2023"] == "product"
    assert kinds["???"] == "unknown"


# --------------------------------------------------------- mapping integrity

@needs_mapping
def test_every_catalog_component_has_explicit_disposition(real_cat):
    """CI gate for monthly catalog commits: every application component in
    the catalog must have an explicit disposition in the mapping — mapped
    (covered by a software component's prefixes), excluded (hit by an
    excluded_prefix), or listed under unmapped. A new component with no
    disposition fails CI, forcing a mapping review."""
    from catalog import _covers
    sw = real_cat.mapping["software_components"]
    unmapped = {u["component"] for u in real_cat.mapping["unmapped"]}
    undispositioned = []
    for comp in real_cat.distinct_components():
        covered = [
            key for key, entry in sw.items()
            if any(_covers(comp, p)
                   for p in entry.get("app_component_prefixes") or [])
            and not any(_covers(comp, x)
                        for x in entry.get("excluded_prefixes") or [])
        ]
        excluded = any(
            _covers(comp, x)
            for entry in sw.values()
            for x in entry.get("excluded_prefixes") or []
        )
        if not (covered or excluded or comp in unmapped):
            undispositioned.append(comp)
        # no component may be silently claimed by two software components
        assert len(covered) <= 1, (
            f"{comp} maps to multiple software components: {covered}"
        )
        # and never both mapped and unmapped
        assert not (covered and comp in unmapped), (
            f"{comp} is both mapped ({covered}) and listed unmapped"
        )
    assert undispositioned == [], (
        "Components without an explicit disposition (map them, exclude "
        f"them, or list them under unmapped): {undispositioned}"
    )


@needs_mapping
def test_every_mapping_entry_has_rationale(real_cat):
    for section in ("software_components", "products"):
        for key, entry in real_cat.mapping[section].items():
            assert entry.get("rationale"), f"{section}/{key} lacks rationale"
    for u in real_cat.mapping["unmapped"]:
        assert u.get("reason"), f"unmapped {u['component']} lacks reason"


@needs_mapping
def test_sap_basis_never_returns_java_or_cloud_notes(real_cat):
    """HARD assertion: cross-stack traps must never leak into SAP_BASIS."""
    hits, _ = real_cat._resolve_software_component("SAP_BASIS", None)
    banned = ("BC-JAS", "BC-XS", "BC-CP", "BC-WD-JAV", "BC-INS-CTC",
              "BC-MID-CON-JCO", "BW-BEX-UDI", "HAN", "BI-BIP", "CEC",
              "SV-SMG")
    leaks = [n["component"] for n in hits
             if n["component"].startswith(banned)]
    assert leaks == [], f"SAP_BASIS leaked cross-stack notes: {leaks}"


@needs_mapping
def test_s4core_never_returns_trap_families(real_cat):
    hits, _ = real_cat._resolve_software_component("S4CORE", None)
    banned = ("BC-JAS", "BC-XS", "HAN", "BI-BIP", "CEC", "SV-SMG")
    leaks = [n["component"] for n in hits
             if n["component"].startswith(banned)]
    assert leaks == [], f"S4CORE leaked cross-stack notes: {leaks}"


# ------------------------------------------------------- end-to-end exposure

@needs_mapping
def test_mohan_stack_paste_end_to_end(real_cat):
    r = real_cat.component_exposure(
        ["S4HANA ON PREMISE 2023", "ABAP PLATFORM 2023"]
    )
    assert len(r["matched"]) == 2
    for m in r["matched"]:
        assert m["classification"] == "product"
        nums = {n["note_number"] for n in m["notes"]}
        assert {"3717897", "3746332"} <= nums, (
            f"{m['input']} missing anchor notes"
        )
        comps = {n["component"] for n in m["notes"]}
        leaks = [c for c in comps
                 if c.startswith(("BC-JAS", "BC-XS", "CEC", "BI-BIP"))]
        assert leaks == [], f"Java/Commerce leak in {m['input']}: {leaks}"
        assert all(n["match_type"] == "mapped_product" for n in m["notes"])
        assert "curated mapping" in m["provenance"]
        assert "mapping-derived" in m["provenance"]
    assert any("2023" in s for s in r["releases_noted"])
    assert "not assessed" in r["releases_noted"][0]


@needs_mapping
def test_s4hana_paste_gets_hcm_hint(real_cat):
    r = real_cat.component_exposure(["S4HANA ON PREMISE 2023"])
    assert r["hints"] == [
        "If this landscape runs HCM (SAP_HR / H4S4), add SAP_HR to your "
        "list to include HR notes."
    ]
    # hint appears once even with multiple S/4HANA items, and not for
    # non-S/4HANA pastes
    r = real_cat.component_exposure(["S4HANA 2023", "SAP S/4HANA 2022"])
    assert len(r["hints"]) == 1
    r = real_cat.component_exposure(["ABAP PLATFORM 2023", "SAP_BASIS"])
    assert "hints" not in r


@needs_mapping
def test_software_component_provenance_label(real_cat):
    """SAP_BASIS has both published affected[] data AND curated-mapping
    fallback coverage; both provenance labels must appear, correctly typed
    per note."""
    r = real_cat.component_exposure(["SAP_BASIS"])
    m = r["matched"][0]
    assert m["classification"] == "software_component"
    assert "published_affected_list" in m["provenance"]
    assert "curated mapping" in m["provenance"]
    match_types = {n["match_type"] for n in m["notes"]}
    assert match_types == {"published_affected_list", "mapped_software_component"}


@needs_mapping
def test_unmapped_software_component_gets_guidance(real_cat):
    r = real_cat.component_exposure(["SAP_ZZFAKE"])
    assert r["matched"] == []
    item = r["could_not_map_or_no_match"]["items"][0]
    assert item["classification"] == "software_component"
    assert "could not map, not assessed" in item["reason"]
    assert "does not mean" in item["reason"]
    # points the user at the app-component taxonomy
    assert "application component" in item["reason"]


@needs_mapping
def test_curated_only_mapping_with_no_published_or_prefix_data(real_cat):
    """UIS4HOP1 has no curated app-component prefixes AND (as of this
    catalog) no published affected[] entries either -> not assessed."""
    r = real_cat.component_exposure(["UIS4HOP1"])
    assert "UIS4HOP1" not in real_cat.by_software_component
    if r["matched"]:
        # If a future catalog publishes UIS4HOP1 data directly, that's a
        # legitimate primary-path match, not a regression.
        assert r["matched"][0]["classification"] == "software_component"
    else:
        item = r["could_not_map_or_no_match"]["items"][0]
        assert "not assessed" in item["reason"]


@needs_mapping
def test_sap_aba_now_matched_via_published_data(real_cat):
    """SAP_ABA has curated mapping with zero prefixes (no app-component
    evidence was ever found), but v2.1's published affected[] data covers
    it directly - primary path wins, so it's matched, not not-assessed."""
    r = real_cat.component_exposure(["SAP_ABA"])
    assert r["matched"]
    m = r["matched"][0]
    assert "published_affected_list" in m["provenance"]
    assert all(n["match_type"] == "published_affected_list" for n in m["notes"])


def test_unknown_product_not_assessed(real_cat):
    r = real_cat.component_exposure(["SOME RANDOM PRODUCT NAME"])
    item = r["could_not_map_or_no_match"]["items"][0]
    assert item["classification"] == "product"
    assert "not assessed" in item["reason"]


# ----------------------------------------------------------------- regression

def test_regression_direct_and_prefix_unchanged(real_cat):
    r = real_cat.component_exposure(["BC-JAS-WEB", "BI-BIP"])
    by_input = {m["input"]: m for m in r["matched"]}
    jas = by_input["BC-JAS-WEB"]
    assert jas["match_mode"] == "exact"
    assert [n["note_number"] for n in jas["notes"]] == ["3727078"]
    assert all(n["match_type"] == "direct" for n in jas["notes"])
    bip = by_input["BI-BIP"]
    assert bip["match_mode"] == "prefix"
    assert all(n["component"].startswith("BI-BIP-") for n in bip["notes"])
    assert all(n["match_type"] == "prefix" for n in bip["notes"])
    assert r["note"]  # null-evidence rule still rides along

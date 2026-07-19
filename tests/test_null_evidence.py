"""Null-evidence probes: unknown identifiers must produce honest not-found
responses with zero fabrication — no invented notes, CVEs, scores, or dates.
"""

from catalog import NULL_EVIDENCE


def test_fake_note_number(cat):
    r = cat.note_details("9999999")
    assert r["found"] is False
    assert "9999999" in r["message"]
    assert "not in this catalog" in r["message"]
    assert NULL_EVIDENCE in r["message"]
    assert "note" not in r  # no fabricated record


def test_fake_cve(cat):
    r = cat.lookup_cve("CVE-2026-99999")
    assert r["found"] is False
    assert "CVE-2026-99999" in r["message"]
    assert NULL_EVIDENCE in r["message"]
    assert "results" not in r


def test_unknown_component(cat):
    r = cat.notes_by_component("ZZ-FAKE")
    assert r["found"] is False
    assert r["match_mode"] == "none"
    assert NULL_EVIDENCE in r["message"]
    assert "results" not in r


def test_exposure_check_all_unknown(cat):
    r = cat.component_exposure(["ZZ-FAKE", "XX-NOPE"])
    assert r["matched"] == []
    items = r["could_not_map_or_no_match"]["items"]
    assert {i["input"] for i in items} == {"ZZ-FAKE", "XX-NOPE"}
    for i in items:
        assert "does not mean" in i["reason"]
    assert "does not mean absence of vulnerability" in (
        r["could_not_map_or_no_match"]["message"]
    )


def test_unknown_month_summary(cat):
    r = cat.patch_day_summary("2031-01")
    assert r["found"] is False
    assert NULL_EVIDENCE in r["message"]


def test_every_success_response_carries_null_evidence(cat):
    """The null-evidence rule must ride along on every tool response."""
    responses = [
        cat.patch_day_summary(),
        cat.search("vulnerability"),
        cat.notes_by_component("BC-JAS"),
        cat.hot_news(),
        cat.lookup_cve("CVE-2026-40128"),
        cat.component_exposure(["BC-JAS"]),
        cat.exploited_notes(),
        cat.compare_months("2026-05", "2026-07"),
        cat.catalog_info(),
    ]
    for resp in responses:
        blob = str(resp)
        assert "does not mean absence of vulnerability" in blob

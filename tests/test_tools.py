"""Per-tool behavior tests against the mini fixture catalog (7 real v2.1
records: 3727078, 3746332, 3763800, 3747787, 3515598, 3687749, 3747367;
one KEV flag on 3515598 is synthetic for testing)."""

from catalog import NULL_EVIDENCE, VERSION_CAVEAT


def test_patch_day_summary_default_latest(cat):
    s = cat.patch_day_summary()
    assert s["month"] == "2026-07"
    assert s["found"] is True
    assert s["total_notes"] == 4
    assert s["counts_by_priority"]["HotNews"] == 2
    hot_numbers = {n["note_number"] for n in s["hot_news"]}
    assert hot_numbers == {"3727078", "3747367"}
    # ranked by CVSS desc: 9.9 before 9.0
    assert s["hot_news"][0]["note_number"] == "3747367"


def test_patch_day_summary_specific_month(cat):
    s = cat.patch_day_summary("2026-04")
    assert s["total_notes"] == 1
    assert s["updated_notes"] == 0  # 3747787 is not an update


def test_search_ranked_by_cvss(cat):
    r = cat.search("vulnerability")
    scores = [x["cvss_score"] for x in r["results"] if x["cvss_score"]]
    assert scores == sorted(scores, reverse=True)


def test_search_filters(cat):
    r = cat.search("", priority="HotNews", min_cvss=9.5)
    assert {x["note_number"] for x in r["results"]} == {"3746332", "3747367", "3687749"}
    r = cat.search("", month="2026-04")
    assert r["result_count"] == 1


def test_note_details_found(cat):
    r = cat.note_details("3727078")
    assert r["found"] is True
    assert r["note"]["cve_ids"] == ["CVE-2026-40128"]


def test_component_exact_match(cat):
    r = cat.notes_by_component("BC-JAS-WEB")
    assert r["found"] is True
    assert r["match_mode"] == "exact"
    assert r["result_count"] == 1
    assert VERSION_CAVEAT in r["version_caveat"]


def test_component_prefix_match(cat):
    r = cat.notes_by_component("BC-JAS")
    assert r["match_mode"] == "prefix"
    assert {x["note_number"] for x in r["results"]} == {"3727078"}


def test_component_prefix_no_false_positives(cat):
    # 'BC' prefix must match BC-* but not CEC-* or FIN-*
    r = cat.notes_by_component("BC")
    comps = {x["component"] for x in r["results"]}
    assert all(c.startswith("BC-") for c in comps)
    assert r["result_count"] == 4


def test_component_since_filter(cat):
    r = cat.notes_by_component("BC-XS-CDX-NJS", since="2026-06")
    assert r["found"] is False


def test_hot_news(cat):
    r = cat.hot_news()
    assert r["result_count"] == 5
    r = cat.hot_news(since="2026-07-01")
    # 3747787's released_on is null (day not public); effective date falls
    # back to its release_month start, which is April - excluded by a July cutoff.
    assert r["result_count"] == 2


def test_lookup_cve_found(cat):
    r = cat.lookup_cve("cve-2026-40128")  # case-insensitive
    assert r["found"] is True
    assert r["results"][0]["note_number"] == "3727078"


def test_component_exposure(cat):
    r = cat.component_exposure(["BC-JAS", "FIN-FSCM-CLM-COP", "ZZ-FAKE"])
    matched = {m["input"]: m for m in r["matched"]}
    assert matched["BC-JAS"]["match_mode"] == "prefix"
    assert matched["FIN-FSCM-CLM-COP"]["match_mode"] == "exact"
    items = r["could_not_map_or_no_match"]["items"]
    assert [i["input"] for i in items] == ["ZZ-FAKE"]
    assert "does not mean" in items[0]["reason"]
    assert "does not mean absence of vulnerability" in (
        r["could_not_map_or_no_match"]["message"]
    )
    assert VERSION_CAVEAT in r["version_caveat"]


def test_exploited_notes(cat):
    r = cat.exploited_notes()
    assert r["result_count"] == 1
    assert r["results"][0]["note_number"] == "3515598"
    assert r["results"][0]["kev_date_added"] == "2026-07-15"


def test_exploited_notes_empty_is_honest(real_cat):
    r = real_cat.exploited_notes()
    # Zero KEV matches in the real catalog must come with the honest framing.
    assert "not that exploitation is impossible" in r["message"]


def test_compare_months(cat):
    r = cat.compare_months("2026-04", "2026-07")
    assert r["found"] is True
    assert r["delta"]["total_notes"] == 3
    assert r["delta"]["hot_news"] == 1
    assert r["month_a"]["max_cvss"] is None  # only the unscored note in April


def test_compare_months_unknown(cat):
    r = cat.compare_months("2026-04", "2031-01")
    assert r["found"] is False
    assert "2031-01" in r["message"]


def test_catalog_info(cat):
    r = cat.catalog_info()
    assert r["catalog_meta"]["note_count"] == 7
    assert NULL_EVIDENCE == r["null_evidence_rule"]


def test_data_quality_flags(cat):
    unscored = cat.note_details("3747787")["note"]
    assert unscored["cvss_score"] is None
    malformed = cat.note_details("3747367")["note"]
    assert malformed["cvss_vector_malformed"] is True
    multi = cat.note_details("3763800")["note"]
    assert multi["multiple_cves"] is True
    assert len(multi["cve_ids"]) == 3


def test_page_only_note_has_null_component(cat):
    """3687749 was added from public pages, not in the pre-v2.1 xlsx export
    -- its legacy application component is honestly null, never fabricated,
    but it's still reachable via its published affected[] data."""
    r = cat.note_details("3687749")["note"]
    assert r["component"] is None
    assert r["affected"]

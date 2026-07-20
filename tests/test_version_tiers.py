"""Version-aware check_component_exposure tiers, against the real v2.1
catalog. Note 3735546 publishes SAP_BASIS versions ending at '758'/'816'
(no '759', no '918') -- a clean fixture for exact-match-only assertions.
"""


def _entry_for(note_number, entries):
    return next(e for e in entries if e["note_number"] == note_number)


def test_tier1_affected_version_confirmed(real_cat):
    r = real_cat.component_exposure(["SAP_BASIS 758"])
    m = r["matched"][0]
    assert m["version_given"] == "758"
    e = _entry_for("3735546", m["notes"])
    assert e["tier"] == 1
    assert e["tier_label"] == "Affected version confirmed"
    assert e["match_type"] == "published_affected_list"
    assert "758" in e["published_versions"]


def test_tier2_component_listed_version_not_in_list(real_cat):
    """918 is not in 3735546's published list -> tier 2, not tier 1, and
    not silently dropped."""
    r = real_cat.component_exposure(["SAP_BASIS 918"])
    m = r["matched"][0]
    e = _entry_for("3735546", m["notes"])
    assert e["tier"] == 2
    assert e["tier_label"] == "Component listed, your version not in the published list"
    assert "not proof of safety" in m["tier_2_caveat"]


def test_no_range_inference_759_never_tier1(real_cat):
    """759 sits between the list's 758 and 816 -- exact-string match only
    means this must NEVER be inferred as tier 1 just because it's 'close
    to' or 'less than' a listed version."""
    r = real_cat.component_exposure(["SAP_BASIS 759"])
    m = r["matched"][0]
    e = _entry_for("3735546", m["notes"])
    assert e["tier"] != 1
    assert e["tier"] == 2
    assert "759" not in e["published_versions"]


def test_tier3_no_version_given(real_cat):
    r = real_cat.component_exposure(["SAP_BASIS"])
    m = r["matched"][0]
    assert m["version_given"] is None
    e = _entry_for("3735546", m["notes"])
    assert e["tier"] == 3
    assert e["tier_label"] == "Component affected, version not assessed"


def test_tier3_fallback_note_with_no_published_data(real_cat):
    """A note reached only through the curated-mapping fallback (no
    affected[] entry for this software component at all) is always tier 3,
    version given or not."""
    r = real_cat.component_exposure(["SAP_BASIS 758"])
    m = r["matched"][0]
    fallback_entries = [n for n in m["notes"]
                        if n["match_type"] == "mapped_software_component"]
    assert fallback_entries, "expected at least one mapping-fallback note"
    for e in fallback_entries:
        assert e["tier"] == 3
        assert "published_versions" not in e


def test_provenance_labels_present(real_cat):
    r = real_cat.component_exposure(["SAP_BASIS 758"])
    m = r["matched"][0]
    assert "published_affected_list" in m["provenance"]
    assert "curated mapping" in m["provenance"]
    assert "mapping-derived" in m["provenance"]


def test_fix_caveat_always_present(real_cat):
    for query in (["SAP_BASIS 758"], ["SAP_BASIS"], ["SAP_BASIS 918"]):
        r = real_cat.component_exposure(query)
        assert "full SAP note" in r["matched"][0]["fix_caveat"]


def test_tier_summary_counts(real_cat):
    r = real_cat.component_exposure(["SAP_BASIS 758"])
    m = r["matched"][0]
    summary = m["tier_summary"]
    assert summary["1_affected_version_confirmed"] >= 1
    assert summary["2_version_not_in_published_list"] >= 1
    assert summary["3_version_not_assessed"] >= 1
    total = sum(summary.values())
    assert total == m["result_count"]

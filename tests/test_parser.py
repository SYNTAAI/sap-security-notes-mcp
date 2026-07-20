"""Tests for scripts/parse_patchday_page.py against tests/fixtures/
patchday_sample.html — a synthetic page covering the tricky real-world
grammar cases: multi-component + repeated-component version lines,
Multiple CVEs with a Related CVEs list, a pre-2026 CVE year, alphanumeric
version tokens, a deliberately malformed line, and an "Update to..."
marker row.
"""

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIXTURE = REPO / "tests" / "fixtures" / "patchday_sample.html"


@pytest.fixture(scope="module")
def records():
    import sys
    sys.path.insert(0, str(REPO / "scripts"))
    from parse_patchday_page import parse_page
    html = FIXTURE.read_text()
    return {r["note_number"]: r for r in
            parse_page(html, "https://example.test/sample.html", "2026-01")}


def test_all_six_rows_parsed(records):
    assert set(records) == {f"900000{i}" for i in range(1, 7)}


def test_repeated_component_style(records):
    r = records["9000001"]
    assert r["versions_unparsed"] is None
    affected = {a["software_component"]: a["versions"] for a in r["affected"]}
    assert affected == {
        "SAP_BASIS": ["700", "701"],
        "KRNL64UC": ["7.53", "7.53EXT"],
    }


def test_multiple_cves_with_related_list(records):
    r = records["9000002"]
    assert r["multiple_cves"] is True
    assert r["cve_ids"] == ["CVE-2026-99002", "CVE-2026-99003"]
    assert r["title"] == "Multiple-CVEs with related list test title"
    affected = {a["software_component"]: a["versions"] for a in r["affected"]}
    assert affected == {"FOO": ["100", "101"]}


def test_pre_2026_cve_year(records):
    r = records["9000003"]
    assert r["cve_ids"] == ["CVE-2019-11111"]
    assert r["multiple_cves"] is False


def test_alphanumeric_versions_kept_verbatim(records):
    r = records["9000004"]
    assert r["versions_unparsed"] is None
    affected = {a["software_component"]: a["versions"] for a in r["affected"]}
    assert affected == {
        "ST-PI": ["2008_1_700", "2008_1_710", "740", "758"],
        "FRMW": ["10.0", "75A"],
    }
    # verbatim, no numeric coercion
    for v in affected["ST-PI"] + affected["FRMW"]:
        assert isinstance(v, str)


def test_deliberately_malformed_line_has_no_partial_emission(records):
    r = records["9000005"]
    assert r["affected"] == []
    assert r["versions_unparsed"] == "SAP BC 4.8"


def test_update_marker_row(records):
    r = records["9000006"]
    assert r["section"] == "updated"
    assert r["update_hint_month"] == "January 2026"
    assert r["title"] == "Update marker test title"
    assert r["cve_ids"] == ["CVE-2026-99006"]


def test_coverage_report(records):
    from parse_patchday_page import coverage_report
    cov = coverage_report(list(records.values()))
    assert cov["total"] == 6
    assert cov["unparsed"] == 1
    assert cov["unparsed_notes"] == ["9000005"]


def test_versions_line_no_partial_guess_on_malformed():
    import sys
    sys.path.insert(0, str(REPO / "scripts"))
    from parse_patchday_page import parse_versions_line
    affected, unparsed = parse_versions_line("SAP BC 4.8")
    assert affected == []
    assert unparsed == "SAP BC 4.8"


def test_versions_line_component_with_multiword_version_token():
    """A version token that itself contains a space (e.g. a typo'd
    'SP01' suffix) must abort the whole line, not silently truncate."""
    import sys
    sys.path.insert(0, str(REPO / "scripts"))
    from parse_patchday_page import parse_versions_line
    affected, unparsed = parse_versions_line("SAP_BASIS 758 SP01, 759")
    assert affected == []
    assert unparsed == "SAP_BASIS 758 SP01, 759"

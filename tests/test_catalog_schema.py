"""Validate the real committed catalog against data/schema.json."""

import json
from pathlib import Path

import jsonschema
import pytest

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def catalog_json():
    return json.loads((REPO / "data" / "notes_catalog.json").read_text())


@pytest.fixture(scope="module")
def schema():
    return json.loads((REPO / "data" / "schema.json").read_text())


def test_catalog_is_schema_valid(catalog_json, schema):
    jsonschema.Draft7Validator(schema).validate(catalog_json)


def test_fixture_is_schema_valid(schema):
    mini = json.loads(
        (REPO / "tests" / "fixtures" / "mini_catalog.json").read_text()
    )
    jsonschema.Draft7Validator(schema).validate(mini)


def test_note_count_matches_meta(catalog_json):
    assert catalog_json["catalog_meta"]["note_count"] == len(
        catalog_json["notes"]
    )


def test_coverage_window(catalog_json):
    meta = catalog_json["catalog_meta"]
    months = {n["release_month"] for n in catalog_json["notes"]}
    assert min(months) == meta["coverage_start"]
    assert max(months) == meta["coverage_end"]


def test_note_numbers_unique(catalog_json):
    numbers = [n["note_number"] for n in catalog_json["notes"]]
    assert len(numbers) == len(set(numbers))


def test_no_zero_cvss(catalog_json):
    # CVSS 0.0 means "not scored" and must be stored as null.
    assert all(n["cvss_score"] != 0.0 for n in catalog_json["notes"])


def test_priority_raw_preserved(catalog_json):
    assert all(n["priority_raw"] for n in catalog_json["notes"])

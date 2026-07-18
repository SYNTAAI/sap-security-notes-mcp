import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from catalog import Catalog  # noqa: E402


@pytest.fixture(scope="session")
def cat():
    """Catalog loaded from the mini fixture (5 real records; one KEV flag
    is synthetic so KEV code paths are testable)."""
    return Catalog(REPO / "tests" / "fixtures" / "mini_catalog.json")


@pytest.fixture(scope="session")
def real_cat():
    """The full committed catalog."""
    return Catalog(REPO / "data" / "notes_catalog.json")

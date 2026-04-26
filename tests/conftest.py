"""
pytest configuration for IISLock&Fix test suite.
Shared fixtures available to all test modules.
"""
import json
import pytest
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def vulnerable_fixture_path():
    return FIXTURES_DIR / "vulnerable_iis_snapshot.json"


@pytest.fixture(scope="session")
def hardened_fixture_path():
    return FIXTURES_DIR / "hardened_iis_snapshot.json"


@pytest.fixture(scope="session")
def ps_sample_path():
    return FIXTURES_DIR / "powershell_sample_output.json"

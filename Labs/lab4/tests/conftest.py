"""Shared pytest fixtures and network isolation for Lab 04 tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "data" / "nvd_sample.json"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disable real network calls via Requests and clear inherited API keys."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def sample_payload() -> dict[str, Any]:
    """Return a fresh deep copy of the synthetic NVD response."""
    return copy.deepcopy(json.loads(SAMPLE_PATH.read_text(encoding="utf-8")))

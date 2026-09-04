"""Smoke tests: the package imports and its module skeleton is intact."""

from __future__ import annotations

import importlib

import pytest

import analyzer

SKELETON_MODULES = [
    "analyzer.core",
    "analyzer.ingest",
    "analyzer.track_a",
    "analyzer.track_b",
    "analyzer.assess",
    "analyzer.report",
    "analyzer.db",
    "analyzer.api",
]


def test_version_is_exposed() -> None:
    assert analyzer.__version__ == "0.1.0"


@pytest.mark.parametrize("name", SKELETON_MODULES)
def test_module_imports(name: str) -> None:
    """Every module in the LLD §2 tree must import cleanly from a fresh interpreter."""
    assert importlib.import_module(name) is not None

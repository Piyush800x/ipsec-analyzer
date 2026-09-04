"""The pinned tshark version must be consistent everywhere it is recorded.

LLD §6.1: Track A parses Wireshark's JSON output. Field names change across
Wireshark releases, and a drift breaks the parser silently -- it produces wrong
values rather than an error. The version is therefore pinned in three places and
these tests assert all three agree:

  1. ``backend/Dockerfile``                              (what gets installed)
  2. ``pyproject.toml`` [tool.ipsec-analyzer.external-tools]  (the record)
  3. the ``tshark`` binary actually on PATH              (what runs)
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


def pinned_version() -> str:
    """The single recorded pin, from pyproject.toml."""
    with (BACKEND_ROOT / "pyproject.toml").open("rb") as fh:
        data = tomllib.load(fh)
    version: str = data["tool"]["ipsec-analyzer"]["external-tools"]["tshark"]
    return version


def test_pin_is_a_concrete_version() -> None:
    """A range or a floating major is not a pin."""
    assert _VERSION_RE.fullmatch(pinned_version()), (
        "tshark must be pinned to an exact x.y.z version, not a range"
    )


def test_dockerfile_matches_pyproject() -> None:
    """The Dockerfile installs exactly the version pyproject.toml records."""
    dockerfile = (BACKEND_ROOT / "Dockerfile").read_text(encoding="utf-8")

    deb = re.search(r"ARG TSHARK_DEB_VERSION=(\S+)", dockerfile)
    plain = re.search(r"ARG TSHARK_VERSION=(\S+)", dockerfile)
    assert deb is not None, "Dockerfile must declare ARG TSHARK_DEB_VERSION"
    assert plain is not None, "Dockerfile must declare ARG TSHARK_VERSION"

    assert plain.group(1) == pinned_version()
    # The Debian revision suffix differs, but the upstream version must match.
    assert deb.group(1).startswith(pinned_version()), (
        f"Dockerfile installs {deb.group(1)}, pyproject pins {pinned_version()}"
    )


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not on PATH")
def test_installed_tshark_matches_pin() -> None:
    """Inside the image -- and on any dev box with tshark -- the binary matches."""
    out = subprocess.run(
        ["tshark", "--version"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout
    found = _VERSION_RE.search(out.splitlines()[0])
    assert found is not None, f"could not parse a version from: {out.splitlines()[0]!r}"
    assert found.group(1) == pinned_version(), (
        f"tshark on PATH is {found.group(1)}, pinned version is {pinned_version()}. "
        "Track A's field-name assumptions are not valid against a different release."
    )

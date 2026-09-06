"""A fake external binary that really runs, on Windows and on POSIX.

Step 4.1's wrapper is a subprocess call, and the only honest way to cover a
subprocess call is to run one. These fakes used to be ``#!/bin/sh`` scripts,
which Windows cannot launch at all: ``CreateProcess`` refuses a file with no
recognised executable format and the test dies with ``WinError 193 -- %1 is
not a valid Win32 application``, which says nothing about shebangs.

So the behaviour is expressed as data here and rendered into whatever the
running platform can actually execute. The body is Python on both sides
rather than shell on one and batch on the other, so there is exactly one set
of quoting rules and the fake cannot drift between platforms.
"""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path
from typing import Any

_BODY = """\
import sys

sys.stdout.write({stdout!r})
sys.stderr.write({stderr!r})
sys.exit({exit_code!r})
"""


def write_fake_binary(
    path: Path, *, stdout: str = "", stderr: str = "", exit_code: int = 0
) -> Path:
    """Write an executable that emits *stdout* and *stderr*, then exits.

    Returns the path to actually launch, which is not always *path*: Windows
    decides what is executable from the extension, so the launcher there is a
    ``.cmd`` shim next to the Python body.
    """
    body = _BODY.format(stdout=stdout, stderr=stderr, exit_code=exit_code)

    if sys.platform == "win32":
        script = path.with_suffix(".py")
        script.write_text(body, encoding="utf-8")
        launcher = path.with_suffix(".cmd")
        # %* forwards the arguments the wrapper passes. Nothing asserts on
        # them today, but a fake that silently swallowed argv would stop being
        # a stand-in the moment one did.
        launcher.write_text(
            f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n',
            encoding="utf-8",
        )
        return launcher

    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


def write_fake_tshark(path: Path, packets: list[dict[str, Any]]) -> Path:
    """A fake tshark that prints *packets* the way ``-T json`` would."""
    return write_fake_binary(path, stdout=json.dumps(packets))

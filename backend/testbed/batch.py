"""Run a sampled matrix as a batch, with resume and a manifest.

Implementation-plan step 2.10.

Dataset generation is an eight-hour unattended job (step 8.3). Three things
follow from that, and they are what this module is:

*It must survive a single failure.* One configuration that will not negotiate
must not cost the other 199 sessions. Failures are recorded and the batch
continues.

*It must survive being killed.* Laptops sleep and SSH sessions drop. The
manifest is rewritten after every session, so a restart resumes rather than
starting over.

*It must not lie about what completed.* A session counts as done only when the
manifest says so **and** its capture and labels are on disk. A manifest can
outlive the files it describes -- someone clears a directory, a disk fills --
and a resume that trusted the manifest alone would silently produce a dataset
with holes in it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from testbed.config import SessionConfig
from testbed.orchestrator import LABELS_NAME, PCAP_NAME, run_session
from testbed.peers import preflight, prune_orphans
from testbed.sampler import load_matrix, sample_configs

log = logging.getLogger(__name__)

MANIFEST_NAME: Final = "manifest.json"
SCHEMA_VERSION: Final = "1.0"

STATUS_COMPLETED: Final = "completed"
STATUS_FAILED: Final = "failed"


@dataclass
class Manifest:
    """The record of which sessions have run, and how they went."""

    path: Path
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
    started_at: str = ""

    @classmethod
    def load_or_create(cls, output_dir: Path) -> Manifest:
        path = output_dir / MANIFEST_NAME
        if path.is_file():
            raw = json.loads(path.read_text(encoding="utf-8"))
            return cls(
                path=path,
                sessions=dict(raw.get("sessions", {})),
                started_at=str(raw.get("started_at", "")),
            )
        return cls(path=path, started_at=datetime.now(tz=UTC).isoformat())

    def save(self) -> None:
        """Rewrite the manifest.

        Written whole, and after every session rather than at the end. A batch
        killed between sessions must leave a manifest describing everything up
        to that point.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": SCHEMA_VERSION,
            "started_at": self.started_at,
            "updated_at": datetime.now(tz=UTC).isoformat(),
            "sessions": self.sessions,
        }
        # Written to a sibling and moved into place, so that a process killed
        # mid-write leaves the previous manifest intact rather than a truncated
        # one that fails to parse on the next resume.
        temporary = self.path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(self.path)

    def is_complete(self, cfg: SessionConfig, output_dir: Path) -> bool:
        """Has ``cfg`` already run successfully, with its output still present?"""
        entry = self.sessions.get(cfg.name)
        if not entry or entry.get("status") != STATUS_COMPLETED:
            return False
        session_dir = output_dir / cfg.name
        return (session_dir / PCAP_NAME).is_file() and (session_dir / LABELS_NAME).is_file()

    def record_success(self, name: str, *, packet_count: int, duration_s: float) -> None:
        attempts = int(self.sessions.get(name, {}).get("attempts", 0)) + 1
        self.sessions[name] = {
            "status": STATUS_COMPLETED,
            "attempts": attempts,
            "packet_count": packet_count,
            "duration_s": round(duration_s, 1),
            "finished_at": datetime.now(tz=UTC).isoformat(),
        }
        self.save()

    def record_failure(self, name: str, error: BaseException) -> None:
        attempts = int(self.sessions.get(name, {}).get("attempts", 0)) + 1
        self.sessions[name] = {
            "status": STATUS_FAILED,
            "attempts": attempts,
            # Truncated: a strongSwan negotiation failure carries a full charon
            # log, and a manifest holding two hundred of them is unreadable.
            # The full text is in the batch log.
            "error": f"{type(error).__name__}: {error}"[:2000],
            "finished_at": datetime.now(tz=UTC).isoformat(),
        }
        self.save()


@dataclass(frozen=True)
class BatchReport:
    """The outcome of one batch invocation."""

    completed: list[str]
    failed: list[str]
    skipped: list[str]
    duration_s: float

    @property
    def ok(self) -> bool:
        return not self.failed


async def run_batch(
    configs: Sequence[SessionConfig],
    output_dir: Path,
    *,
    resume: bool = True,
    stop_on_error: bool = False,
    skip_preflight: bool = False,
) -> BatchReport:
    """Run every configuration, recording progress as it goes."""
    started = time.monotonic()
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = Manifest.load_or_create(output_dir)

    if not skip_preflight:
        await preflight()

    # A previous run killed mid-session leaves containers and a network behind,
    # and a few hundred of those will exhaust the address pools of the daemon.
    containers, networks = await prune_orphans()
    if containers or networks:
        log.info("cleaned up %d orphaned containers and %d networks", containers, networks)

    completed: list[str] = []
    failed: list[str] = []
    skipped: list[str] = []

    for index, cfg in enumerate(configs, start=1):
        if resume and manifest.is_complete(cfg, output_dir):
            skipped.append(cfg.name)
            log.info("[%d/%d] %s already done, skipping", index, len(configs), cfg.name)
            continue

        log.info("[%d/%d] %s", index, len(configs), cfg.name)
        try:
            result = await run_session(cfg, output_dir)
        except Exception as exc:
            failed.append(cfg.name)
            manifest.record_failure(cfg.name, exc)
            log.error("[%s] failed: %s", cfg.name, exc)
            if stop_on_error:
                raise
            # One bad configuration must not leave its containers behind for
            # the next two hundred sessions to contend with.
            await prune_orphans()
            continue

        completed.append(cfg.name)
        manifest.record_success(
            cfg.name, packet_count=result.packet_count, duration_s=result.duration_s
        )

    elapsed = time.monotonic() - started
    log.info(
        "batch finished: %d completed, %d failed, %d skipped, %.0fs",
        len(completed),
        len(failed),
        len(skipped),
        elapsed,
    )
    if failed:
        log.warning("failed sessions: %s", ", ".join(failed))
    return BatchReport(completed=completed, failed=failed, skipped=skipped, duration_s=elapsed)


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point: ``python -m testbed.batch``."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path, help="where sessions are written")
    parser.add_argument(
        "--limit", type=int, default=None, help="run only the first N configurations"
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="re-run configurations the manifest already records as completed",
    )
    parser.add_argument(
        "--stop-on-error", action="store_true", help="abort the batch on the first failure"
    )
    parser.add_argument(
        "--duration", type=int, default=None, help="override the per-session traffic duration"
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    for noisy in ("docker", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    configs = sample_configs(load_matrix())
    if args.duration is not None:
        configs = [cfg.model_copy(update={"duration_s": args.duration}) for cfg in configs]
    if args.limit is not None:
        configs = configs[: args.limit]

    report = asyncio.run(
        run_batch(
            configs,
            args.output_dir,
            resume=not args.no_resume,
            stop_on_error=args.stop_on_error,
        )
    )
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())

"""Label verification: Track A output against ground truth. Step 8.2.

The harness that answers "does the parser actually reproduce what we
configured?" across a whole batch. Its hardest job is *not* being a strict
equality check, and that is worth being explicit about, because the obvious
implementation is actively harmful here.

Three outcomes are correct, and only one of them is equality:

``MATCH``
    Track A observed the value and it equals the configured one. The result
    that step 8.1's Done-when is really asking for.

``HONEST_GAP``
    Ground truth's ``not_observable_from_ike`` says no parser can recover this
    field from this capture, and Track A reported ``UNAVAILABLE``. This is a
    *pass*. LLD section 10.2 and the step 2.7 notes are explicit that without
    this, the obvious way to turn the harness green would be to teach the
    parser to guess -- which is the one thing the whole product must not do.

``INFERRED``
    Track A reported the field as an inference rather than an observation. Not
    scored either way, and reported separately. LLD section 6.4 requires the
    Child SA's crypto to be inferred from the IKE SA's, and this project's own
    matrix deliberately configures IKE on CBC while ESP carries AEAD, so those
    inferences are *expected to diverge* on every GCM row (see CHANGELOG's
    Phase 4 open spec question). Counting them as mismatches would mean the
    harness only goes green if Track A starts lying.

And two are failures:

``MISMATCH``
    Observed, and wrong. A real parser bug.

``FABRICATED``
    Ground truth says this field is not observable from this capture, and
    Track A reported a value for it anyway. Worse than a mismatch: a wrong
    value the report will present as a fact.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from analyzer.core.enums import Provenance
from analyzer.core.schema import SecurityAssociation

ParseCallable = Callable[[Path], list[SecurityAssociation]]
"""How the batch verifier reaches Track A. Injected rather than imported so
the harness is testable without tshark, and so a Track A change cannot
silently alter what "verified" means here."""

LABELS_NAME = "labels.json"
PCAP_NAME = "capture.pcap"


class Outcome(StrEnum):
    MATCH = "match"
    HONEST_GAP = "honest_gap"
    INFERRED = "inferred"
    MISMATCH = "mismatch"
    FABRICATED = "fabricated"
    NOT_REPORTED = "not_reported"


FAILURES: frozenset[Outcome] = frozenset({Outcome.MISMATCH, Outcome.FABRICATED})

COMPARABLE_FIELDS: tuple[str, ...] = (
    "ike_version",
    "ike_exchange_mode",
    "encryption_alg",
    "encryption_keylen",
    "integrity_alg",
    "prf_alg",
    "dh_group",
    "operating_mode",
    "pfs_enabled",
    "auth_method",
    "negotiated_lifetime_s",
)
"""The ``expected`` keys that map onto a ``SecurityAssociation`` attribute.

``traffic_class`` is in ``expected`` too but belongs to Track B's predictions
rather than to any single attribute, so it is checked separately once a
classifier exists.
"""


@dataclass(frozen=True, slots=True)
class FieldResult:
    field: str
    outcome: Outcome
    expected: Any
    actual: Any
    provenance: str | None
    note: str | None = None

    @property
    def failed(self) -> bool:
        return self.outcome in FAILURES


@dataclass(frozen=True, slots=True)
class SessionResult:
    name: str
    results: tuple[FieldResult, ...]

    @property
    def failures(self) -> tuple[FieldResult, ...]:
        return tuple(r for r in self.results if r.failed)

    @property
    def passed(self) -> bool:
        return not self.failures

    def count(self, outcome: Outcome) -> int:
        return sum(1 for r in self.results if r.outcome is outcome)


@dataclass(slots=True)
class BatchReport:
    sessions: list[SessionResult] = field(default_factory=list)
    unreadable: list[tuple[str, str]] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.unreadable and all(session.passed for session in self.sessions)

    def totals(self) -> dict[Outcome, int]:
        return {
            outcome: sum(session.count(outcome) for session in self.sessions) for outcome in Outcome
        }

    def render(self) -> str:
        lines = [f"{len(self.sessions)} sessions verified"]
        totals = self.totals()
        for outcome in Outcome:
            if totals[outcome]:
                lines.append(f"  {outcome.value:<14} {totals[outcome]}")

        for session in self.sessions:
            if session.passed:
                continue
            lines.append(f"\n{session.name}:")
            for result in session.failures:
                lines.append(
                    f"  {result.outcome.value.upper():<11} {result.field}: "
                    f"expected {result.expected!r}, got {result.actual!r} "
                    f"({result.provenance})"
                )

        for name, reason in self.unreadable:
            lines.append(f"\n{name}: could not be verified -- {reason}")

        lines.append("")
        lines.append("PASS" if self.passed else "FAIL")
        return "\n".join(lines)


def _normalise(value: Any) -> Any:
    """Ground truth stores enum *values*; the contract holds enum members."""
    return value.value if hasattr(value, "value") and not isinstance(value, bool | int) else value


def verify_session(labels: dict[str, Any], sa: SecurityAssociation) -> SessionResult:
    """Compare one parsed SA against one ``labels.json``."""
    expected: dict[str, Any] = labels.get("expected", {})
    unobservable: dict[str, str] = labels.get("not_observable_from_ike", {})
    name = str(labels.get("name", "unnamed"))

    results = []
    for field_name in COMPARABLE_FIELDS:
        if field_name not in expected:
            continue
        attribute = getattr(sa, field_name, None)
        if attribute is None:
            results.append(
                FieldResult(field_name, Outcome.NOT_REPORTED, expected[field_name], None, None)
            )
            continue

        wanted = expected[field_name]
        actual = _normalise(attribute.value)
        provenance = attribute.provenance.value
        reason = unobservable.get(field_name)

        if attribute.provenance is Provenance.UNAVAILABLE:
            # An honest gap only counts as one where ground truth agrees the
            # field is unrecoverable. Elsewhere it is a parser that gave up.
            outcome = Outcome.HONEST_GAP if reason is not None else Outcome.NOT_REPORTED
        elif reason is not None:
            outcome = Outcome.FABRICATED
        elif attribute.provenance is Provenance.INFERRED:
            outcome = Outcome.INFERRED
        elif actual == wanted:
            outcome = Outcome.MATCH
        else:
            outcome = Outcome.MISMATCH

        results.append(FieldResult(field_name, outcome, wanted, actual, provenance, attribute.note))

    return SessionResult(name=name, results=tuple(results))


def verify_batch(batch_dir: Path, *, parse: ParseCallable) -> BatchReport:
    """Verify every session directory under *batch_dir*."""
    report = BatchReport()
    for session_dir in sorted(p for p in batch_dir.iterdir() if p.is_dir()):
        labels_path = session_dir / LABELS_NAME
        pcap_path = session_dir / PCAP_NAME
        if not labels_path.exists() or not pcap_path.exists():
            report.unreadable.append((session_dir.name, "missing capture.pcap or labels.json"))
            continue

        try:
            labels = json.loads(labels_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            report.unreadable.append((session_dir.name, f"labels.json unreadable: {exc}"))
            continue

        try:
            sas = parse(pcap_path)
        except Exception as exc:
            report.unreadable.append(
                (session_dir.name, f"parser raised {type(exc).__name__}: {exc}")
            )
            continue

        if not sas:
            report.unreadable.append((session_dir.name, "no security associations were parsed"))
            continue

        report.sessions.append(verify_session(labels, sas[0]))

    return report


def _main(argv: list[str] | None = None) -> int:
    """``python -m testbed.verify <batch-dir>``. Step 8.2's entry point."""
    import argparse
    import sys

    from analyzer.ingest.flow import assemble_flows
    from analyzer.ingest.reader import read_packets
    from analyzer.track_a.correlate import run_track_a

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("batch_dir", type=Path)
    parser.add_argument("--tshark", default="tshark", help="tshark binary to use")
    args = parser.parse_args(argv)

    def parse(pcap: Path) -> list[SecurityAssociation]:
        pairs = assemble_flows(read_packets(pcap).packets)
        return run_track_a(pcap, pairs, tshark_bin=args.tshark)

    report = verify_batch(args.batch_dir, parse=parse)
    sys.stdout.write(report.render() + "\n")
    return 0 if report.passed else 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(_main())

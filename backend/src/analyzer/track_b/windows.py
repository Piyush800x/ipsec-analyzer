"""Windowing and dataset assembly for ML. Step 9.5, LLD 7.6.

Two jobs, and the second is the one that decides whether any accuracy number
this project reports means anything.

**Windowing.** LLD section 7.6: fixed 10-second windows at 50% overlap, per SA,
scored only when the window holds at least 20 packets. A window is turned into
an ``SAPair`` covering just its packets and handed to the existing
``features.extract``, so a window's feature vector is computed by exactly the
same code as a whole capture's -- there is no second implementation to drift.

**Splitting.** LLD section 7.6 again, emphatically: *split by configuration and
session, never by window*. Two windows from one capture are minutes apart at
most, share a tunnel, a cipher, a seed and a generator, and are very nearly the
same measurement twice. Putting one in train and the other in test measures how
well a model recognises a capture it has already seen, which is a number that
looks like generalisation, tends to come out above 0.95, and is worthless.

The splitter here goes one level stricter than sessions and splits by
*configuration*, so a configuration's repeat runs (step 8.3) cannot straddle
the boundary either -- they share the tunnel and differ only in traffic
parameters, and treating them as independent would leak in the same way one
level down. ``split_sessions`` proves the property rather than documenting it,
and ``tests/test_track_b_dataset.py`` proves it again from the outside.

Stratification is by traffic class, because that is the label ML-1 predicts and
an unstratified split of 62 configurations across 7 classes will produce a test
fold missing a class outright.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import polars as pl

from analyzer.ingest.flow import Flow, SAPair, assemble_flows
from analyzer.ingest.reader import PacketRecord, read_packets
from analyzer.track_b.features import extract, sequence_features

log = logging.getLogger(__name__)

WINDOW_S: Final = 10.0
"""LLD section 7.6: fixed 10-second windows."""

WINDOW_STRIDE_S: Final = WINDOW_S / 2
"""50% overlap. Overlapping windows are why the split must be by session: two
adjacent windows literally share half their packets."""

MIN_WINDOW_PACKETS: Final = 20
"""LLD section 7.6: below this a window is not scored at all, rather than
scored badly. A 3-packet window's percentile features are noise wearing the
same column names as a real measurement."""

LABELS_NAME: Final = "labels.json"
PCAP_NAME: Final = "capture.pcap"


@dataclass(frozen=True, slots=True)
class Window:
    """One scored window: its features, its label, and where it came from.

    ``config_name`` and ``session_name`` are carried on every row precisely so
    that the splitter can group by them. A feature matrix that had dropped them
    could still be split -- by row, wrongly, with nothing to say it was wrong.
    """

    config_name: str
    session_name: str
    traffic_class: str
    start_ts: float
    features: dict[str, float]
    sequence: list[float]

    @property
    def packet_count(self) -> int:
        return int(self.features.get("packet_count", 0))


def _slice_flow(flow: Flow, start_ts: float, end_ts: float) -> Flow | None:
    packets = tuple(p for p in flow.packets if start_ts <= p.ts < end_ts)
    if not packets:
        return None
    return Flow(
        key=flow.key,
        packets=packets,
        start_ts=packets[0].ts,
        end_ts=packets[-1].ts,
    )


def window_pair(pair: SAPair) -> Iterator[tuple[float, SAPair]]:
    """Split *pair* into overlapping windows, yielding ``(start_ts, pair)``.

    A window with no forward-direction packets is skipped rather than yielded
    with an empty forward flow: ``SAPair.forward`` is not optional, and a flow
    of zero packets is not a window that was quiet, it is a window that was not
    part of this SA.
    """
    packets = pair.forward.packets + (pair.reverse.packets if pair.reverse else ())
    if not packets:
        return
    first = min(p.ts for p in packets)
    last = max(p.ts for p in packets)

    start = first
    while start <= last:
        end = start + WINDOW_S
        forward = _slice_flow(pair.forward, start, end)
        if forward is not None:
            reverse = _slice_flow(pair.reverse, start, end) if pair.reverse else None
            yield start, SAPair(forward=forward, reverse=reverse, paired=reverse is not None)
        start += WINDOW_STRIDE_S


def windows_for_session(
    packets: list[PacketRecord],
    *,
    config_name: str,
    session_name: str,
    traffic_class: str,
) -> list[Window]:
    """Every scorable window in one capture."""
    windows: list[Window] = []
    for pair in assemble_flows(packets):
        for start_ts, windowed in window_pair(pair):
            total = len(windowed.forward.packets) + (
                len(windowed.reverse.packets) if windowed.reverse else 0
            )
            if total < MIN_WINDOW_PACKETS:
                continue
            windows.append(
                Window(
                    config_name=config_name,
                    session_name=session_name,
                    traffic_class=traffic_class,
                    start_ts=start_ts,
                    features=extract(windowed),
                    sequence=sequence_features(windowed),
                )
            )
    return windows


def config_name_of(session_name: str) -> str:
    """The configuration a session belongs to, stripping a repeat suffix.

    ``with_repeats`` names run *n* of a configuration ``<config>-r<n>`` (step
    8.3). Recovering the configuration from the directory name means the
    splitter needs nothing the dataset does not already carry on disk.
    """
    head, sep, tail = session_name.rpartition("-r")
    if sep and tail.isdigit():
        return head
    return session_name


def load_dataset(sessions_dir: Path) -> list[Window]:
    """Read every session under *sessions_dir* into scored windows.

    Sessions that cannot be read are logged and skipped rather than aborting
    the run: an eight-hour generation batch that produced one truncated capture
    should still yield a dataset, and the count reported at the end is the
    honest one.
    """
    windows: list[Window] = []
    for session_dir in sorted(p for p in sessions_dir.iterdir() if p.is_dir()):
        labels_path = session_dir / LABELS_NAME
        pcap_path = session_dir / PCAP_NAME
        if not labels_path.exists() or not pcap_path.exists():
            log.warning("%s: missing capture or labels, skipped", session_dir.name)
            continue
        try:
            labels = json.loads(labels_path.read_text(encoding="utf-8"))
            packets = read_packets(pcap_path).packets
        except Exception as exc:
            log.warning("%s: unreadable (%s), skipped", session_dir.name, exc)
            continue

        traffic_class = labels.get("expected", {}).get("traffic_class")
        if not traffic_class:
            log.warning("%s: labels carry no traffic_class, skipped", session_dir.name)
            continue

        session_windows = windows_for_session(
            packets,
            config_name=config_name_of(session_dir.name),
            session_name=session_dir.name,
            traffic_class=traffic_class,
        )
        log.info("%s: %d windows (%s)", session_dir.name, len(session_windows), traffic_class)
        windows.extend(session_windows)
    return windows


# ===========================================================================
# Splitting -- the part LLD section 7.6 says must never be done by window
# ===========================================================================


@dataclass(frozen=True, slots=True)
class Split:
    """Three disjoint sets of *configuration names*, not of rows.

    Calibration is its own split because LLD section 7.6 requires it be
    disjoint from both train and test: a temperature fitted on the training
    fold inherits the training fold's overconfidence, and one fitted on test
    turns the ECE figure into a training metric.
    """

    train: tuple[str, ...]
    calibration: tuple[str, ...]
    test: tuple[str, ...]

    def fold_of(self, config_name: str) -> str | None:
        for name, members in (
            ("train", self.train),
            ("calibration", self.calibration),
            ("test", self.test),
        ):
            if config_name in members:
                return name
        return None


def _stable_hash(value: str, salt: str) -> int:
    """A deterministic hash. ``hash()`` is salted per process, so a split built
    with it would differ between runs and make NFR-4 unprovable."""
    digest = hashlib.sha256(f"{salt}:{value}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def split_configs(
    windows: Sequence[Window],
    *,
    calibration_fraction: float = 0.15,
    test_fraction: float = 0.20,
    salt: str = "ipsec-analyzer-9.5",
) -> Split:
    """Assign whole configurations to train/calibration/test, stratified by class.

    Stratified because 62 configurations spread over 7 traffic classes will,
    under an unstratified 20% draw, routinely produce a test fold with no
    examples of some class at all -- and a macro-F1 computed over a fold
    missing a class is not the number PRD section 8.4 asks for.

    Deterministic because the split is part of the model's provenance: a
    reported score has to be reproducible from the dataset alone, and a
    randomly seeded shuffle would make "the test set" a thing that existed only
    in the session that trained the model.
    """
    by_class: dict[str, set[str]] = {}
    for window in windows:
        by_class.setdefault(window.traffic_class, set()).add(window.config_name)

    train: list[str] = []
    calibration: list[str] = []
    test: list[str] = []

    for _traffic_class, configs in sorted(by_class.items()):
        ordered = sorted(configs, key=lambda name: _stable_hash(name, salt))
        n = len(ordered)
        n_test = max(1, round(n * test_fraction)) if n > 2 else (1 if n > 1 else 0)
        n_cal = max(1, round(n * calibration_fraction)) if n - n_test > 2 else 0

        test.extend(ordered[:n_test])
        calibration.extend(ordered[n_test : n_test + n_cal])
        train.extend(ordered[n_test + n_cal :])

    return Split(
        train=tuple(sorted(train)),
        calibration=tuple(sorted(calibration)),
        test=tuple(sorted(test)),
    )


def to_frame(windows: Sequence[Window], split: Split) -> pl.DataFrame:
    """The feature matrix: one row per window, with its fold and provenance.

    The fold is a *column* rather than three separate frames on purpose. Every
    downstream consumer then filters the same object, and a row can never end
    up in two folds because there is only one place recording which fold it is
    in.
    """
    rows: list[dict[str, Any]] = []
    for window in windows:
        fold = split.fold_of(window.config_name)
        if fold is None:
            continue
        row: dict[str, Any] = {
            "config_name": window.config_name,
            "session_name": window.session_name,
            "traffic_class": window.traffic_class,
            "fold": fold,
            "start_ts": window.start_ts,
        }
        row.update(window.features)
        row.update({f"seq_{i:03d}": v for i, v in enumerate(window.sequence)})
        rows.append(row)
    return pl.DataFrame(rows)


def feature_columns(frame: pl.DataFrame) -> list[str]:
    """The tabular feature columns: everything that is not provenance or sequence."""
    excluded = {"config_name", "session_name", "traffic_class", "fold", "start_ts"}
    return [name for name in frame.columns if name not in excluded and not name.startswith("seq_")]


def sequence_columns(frame: pl.DataFrame) -> list[str]:
    return [name for name in frame.columns if name.startswith("seq_")]

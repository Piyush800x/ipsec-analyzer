"""Steps 9.5-9.10: windowing, the split, calibration and attribution.

Step 9.5's **Done when** is "the splitter is tested to prove no session appears
in more than one split", and that is what the first class here does -- from the
outside, over a dataset built to try to break it, rather than by reading the
implementation.

The leak these tests exist to prevent is not hypothetical. Windows overlap by
50%, so two adjacent windows share half their packets outright; a window-level
split puts one of them in train and the other in test and reports an accuracy
that is mostly a memory test. It comes out high, which is exactly why nobody
questions it.
"""

from __future__ import annotations

import numpy as np
import pytest

from analyzer.ingest.flow import Flow, SAPair
from analyzer.ingest.reader import FlowKey, PacketRecord
from analyzer.track_b.calibration import (
    expected_calibration_error,
    fit_isotonic,
    fit_temperature,
    reliability_bins,
)
from analyzer.track_b.windows import (
    MIN_WINDOW_PACKETS,
    WINDOW_S,
    Window,
    config_name_of,
    feature_columns,
    sequence_columns,
    split_configs,
    to_frame,
    window_pair,
    windows_for_session,
)

CLASSES = ("icmp", "web", "voip", "video", "email", "file_transfer", "messaging")


def _packet(index: int, ts: float, src: str, dst: str, spi: int, length: int) -> PacketRecord:
    return PacketRecord(
        index=index,
        ts=ts,
        ip_version=4,
        src=src,
        dst=dst,
        proto="esp",
        spi=spi,
        seq=index,
        ip_payload_len=length + 8,
        esp_payload_len=length,
        captured_len=length + 28,
        orig_len=length + 28,
    )


def _session_packets(*, seconds: float, rate: float, length: int = 100) -> list[PacketRecord]:
    """A steady bidirectional flow, long enough to produce several windows."""
    packets = []
    index = 0
    step = 1.0 / rate
    ts = 0.0
    while ts < seconds:
        packets.append(_packet(index, ts, "10.0.0.1", "10.0.0.2", 1, length))
        packets.append(_packet(index + 1, ts + step / 2, "10.0.0.2", "10.0.0.1", 2, length))
        index += 2
        ts += step
    return packets


def _windows(config: str, session: str, traffic_class: str, seconds: float = 40.0) -> list[Window]:
    return windows_for_session(
        _session_packets(seconds=seconds, rate=10.0),
        config_name=config,
        session_name=session,
        traffic_class=traffic_class,
    )


def _dataset() -> list[Window]:
    """Two configurations per class, each with two repeat runs."""
    windows: list[Window] = []
    for traffic_class in CLASSES:
        for config_index in (0, 1):
            config = f"cfg-{traffic_class}-{config_index}"
            windows.extend(_windows(config, config, traffic_class))
            windows.extend(_windows(config, f"{config}-r2", traffic_class))
    return windows


# ===========================================================================
# Step 9.5: windowing
# ===========================================================================


class TestWindowing:
    def test_windows_overlap_by_half(self) -> None:
        packets = _session_packets(seconds=40.0, rate=10.0)
        forward = tuple(p for p in packets if p.src == "10.0.0.1")
        reverse = tuple(p for p in packets if p.src == "10.0.0.2")
        pair = SAPair(
            forward=Flow(
                key=FlowKey("10.0.0.1", "10.0.0.2", 1, "esp"),
                packets=forward,
                start_ts=forward[0].ts,
                end_ts=forward[-1].ts,
            ),
            reverse=Flow(
                key=FlowKey("10.0.0.2", "10.0.0.1", 2, "esp"),
                packets=reverse,
                start_ts=reverse[0].ts,
                end_ts=reverse[-1].ts,
            ),
            paired=True,
        )

        starts = [start for start, _ in window_pair(pair)]

        assert len(starts) > 1
        assert starts[1] - starts[0] == pytest.approx(WINDOW_S / 2)

    def test_sparse_windows_are_not_scored(self) -> None:
        """LLD section 7.6's 20-packet floor. A 3-packet window's percentile
        features are noise wearing a real measurement's column names."""
        sparse = windows_for_session(
            _session_packets(seconds=40.0, rate=0.2),
            config_name="cfg",
            session_name="cfg",
            traffic_class="messaging",
        )

        assert all(window.packet_count >= MIN_WINDOW_PACKETS for window in sparse)

    def test_windows_carry_their_provenance(self) -> None:
        """Without these two columns the frame could still be split -- by row,
        wrongly, with nothing to say it was wrong."""
        for window in _windows("cfg-a", "cfg-a-r2", "web"):
            assert window.config_name == "cfg-a"
            assert window.session_name == "cfg-a-r2"

    def test_repeat_suffix_maps_back_to_its_configuration(self) -> None:
        assert config_name_of("s001-ikev2-aes-r3") == "s001-ikev2-aes"
        assert config_name_of("s001-ikev2-aes") == "s001-ikev2-aes"

    def test_a_name_ending_in_r_and_a_word_is_not_a_repeat(self) -> None:
        """``-rekey`` is part of a configuration name, not a run number."""
        assert config_name_of("weak-reference") == "weak-reference"
        assert config_name_of("s000-rekey") == "s000-rekey"


# ===========================================================================
# Step 9.5's Done when: no session in more than one split
# ===========================================================================


class TestSplitLeakage:
    def test_no_session_appears_in_more_than_one_fold(self) -> None:
        """Step 9.5's stated acceptance condition.

        Asserted as the conjunction of the two facts that actually establish it,
        rather than by reading folds back off the assembled frame. That weaker
        version cannot fail: ``Split.fold_of`` returns the *first* fold holding a
        configuration, so a configuration wrongly placed in two folds would be
        silently rendered as one and the test would pass over the bug it exists
        to catch.
        """
        windows = _dataset()
        split = split_configs(windows)

        # 1. Each session belongs to exactly one configuration.
        configs_per_session: dict[str, set[str]] = {}
        for window in windows:
            configs_per_session.setdefault(window.session_name, set()).add(window.config_name)
        assert all(len(configs) == 1 for configs in configs_per_session.values())

        # 2. No configuration is in more than one fold. Counted across all
        #    three, so a configuration in two folds shows up as a count of 2.
        placements: dict[str, int] = {}
        for members in (split.train, split.calibration, split.test):
            for config in members:
                placements[config] = placements.get(config, 0) + 1
        duplicated = [config for config, count in placements.items() if count > 1]
        assert not duplicated, f"configurations placed in multiple folds: {duplicated}"

        # Together those two mean a session's windows are all in one fold, which
        # the assembled frame should then also show.
        frame = to_frame(windows, split)
        for session in configs_per_session:
            folds = set(frame.filter(frame["session_name"] == session)["fold"].to_list())
            assert len(folds) == 1, f"{session} spans folds {folds}"

    def test_no_configuration_appears_in_more_than_one_fold(self) -> None:
        """Stricter than sessions, and the reason repeats are safe.

        A configuration's repeat runs share the tunnel and differ only in
        traffic parameters. Splitting by session alone would put run 1 in train
        and run 2 in test, which leaks the configuration even though no single
        session spans folds.
        """
        windows = _dataset()
        split = split_configs(windows)

        assert not set(split.train) & set(split.calibration)
        assert not set(split.train) & set(split.test)
        assert not set(split.calibration) & set(split.test)

    def test_repeats_of_one_configuration_land_together(self) -> None:
        windows = _dataset()
        frame = to_frame(windows, split_configs(windows))

        for config in {window.config_name for window in windows}:
            folds = set(frame.filter(frame["config_name"] == config)["fold"].to_list())
            assert len(folds) == 1, f"{config} spans {folds}"

    def test_every_class_reaches_the_test_fold(self) -> None:
        """An unstratified draw routinely leaves a class out of test entirely,
        and a macro-F1 over a fold missing a class is not PRD 8.4's number."""
        windows = _dataset()
        frame = to_frame(windows, split_configs(windows))
        test = frame.filter(frame["fold"] == "test")

        assert set(test["traffic_class"].to_list()) == set(CLASSES)

    def test_the_split_is_deterministic(self) -> None:
        """A reported score has to be reproducible from the dataset alone.
        ``hash()`` is salted per process, which is why the splitter does not
        use it."""
        windows = _dataset()

        assert split_configs(windows) == split_configs(windows)

    def test_folds_together_cover_every_configuration(self) -> None:
        windows = _dataset()
        split = split_configs(windows)

        covered = set(split.train) | set(split.calibration) | set(split.test)
        assert covered == {window.config_name for window in windows}

    def test_frame_separates_features_from_provenance(self) -> None:
        windows = _dataset()
        frame = to_frame(windows, split_configs(windows))

        features = feature_columns(frame)
        assert "traffic_class" not in features, "the label must not be a feature"
        assert "config_name" not in features
        assert "fold" not in features
        assert len(sequence_columns(frame)) == 128


# ===========================================================================
# Step 9.8: calibration
# ===========================================================================


class TestCalibration:
    def test_perfect_calibration_scores_zero(self) -> None:
        """A model right exactly as often as it claims to be."""
        probabilities = np.array([[1.0, 0.0], [1.0, 0.0], [0.0, 1.0], [0.0, 1.0]])
        y = np.array([0, 0, 1, 1])

        assert expected_calibration_error(probabilities, y) == pytest.approx(0.0)

    def test_confident_and_wrong_scores_one(self) -> None:
        """The failure PRD section 8.3 is about: certainty with no basis."""
        probabilities = np.array([[1.0, 0.0], [1.0, 0.0]])
        y = np.array([1, 1])

        assert expected_calibration_error(probabilities, y) == pytest.approx(1.0)

    def test_temperature_scaling_does_not_change_any_prediction(self) -> None:
        """The property that makes it safe: it moves confidences, not answers.

        If calibration could change a prediction, the accuracy figure reported
        before it would be conditional on a step taken after it.
        """
        rng = np.random.default_rng(0)
        logits = rng.normal(size=(200, 4)) * 4.0
        y = logits.argmax(axis=1)

        temperature = fit_temperature(logits, y)

        assert (temperature.apply(logits).argmax(axis=1) == logits.argmax(axis=1)).all()

    def test_temperature_improves_an_overconfident_model(self) -> None:
        rng = np.random.default_rng(1)
        logits = rng.normal(size=(400, 3)) * 8.0
        # Right two thirds of the time while claiming near-certainty.
        y = logits.argmax(axis=1).copy()
        y[::3] = (y[::3] + 1) % 3

        temperature = fit_temperature(logits, y)

        assert temperature.ece_after < temperature.ece_before
        assert temperature.value > 1.0, "an overconfident model needs a temperature above 1"

    def test_isotonic_returns_a_distribution(self) -> None:
        rng = np.random.default_rng(2)
        raw = rng.random((200, 3))
        probabilities = raw / raw.sum(axis=1, keepdims=True)
        y = probabilities.argmax(axis=1)

        calibrated = fit_isotonic(probabilities, y, 3).apply(probabilities)

        assert calibrated.sum(axis=1) == pytest.approx(np.ones(len(y)))

    def test_isotonic_survives_a_class_missing_from_the_calibration_fold(self) -> None:
        """A small calibration fold can simply not contain a class. That must
        pass the class's probabilities through, not flatten them to a constant."""
        probabilities = np.array([[0.7, 0.2, 0.1], [0.6, 0.3, 0.1], [0.8, 0.1, 0.1]])
        y = np.array([0, 0, 0])

        calibrated = fit_isotonic(probabilities, y, 3).apply(probabilities)

        assert np.isfinite(calibrated).all()
        assert calibrated.sum(axis=1) == pytest.approx(np.ones(3))

    def test_reliability_bins_account_for_every_row(self) -> None:
        rng = np.random.default_rng(3)
        raw = rng.random((100, 2))
        probabilities = raw / raw.sum(axis=1, keepdims=True)
        y = rng.integers(0, 2, size=100)

        assert sum(int(row["count"]) for row in reliability_bins(probabilities, y)) == 100

    def test_exported_knots_reproduce_the_fitted_calibrator(self) -> None:
        """Inference applies the exported knots, training applies the estimator.

        If those two disagreed, a confidence in a report would differ from the
        confidence the model was evaluated with -- and the ECE figure committed
        to the docs would describe something the deployment does not do.
        """
        from analyzer.track_b.calibration import apply_knots

        rng = np.random.default_rng(4)
        raw = rng.random((150, 4))
        probabilities = raw / raw.sum(axis=1, keepdims=True)
        y = rng.integers(0, 4, size=150)

        calibrator = fit_isotonic(probabilities, y, 4)

        assert apply_knots(probabilities, calibrator.knots()) == pytest.approx(
            calibrator.apply(probabilities)
        )


# ===========================================================================
# load_dataset: reading a session tree off disk
# ===========================================================================


class TestLoadDataset:
    """``load_dataset`` is what stands between a generation run and training.

    Its failure mode is silence: a session it cannot read is skipped, and a
    dataset quietly missing a fifth of its sessions still trains, still scores,
    and still looks fine.
    """

    def _session(self, root, name: str, traffic_class: str, *, seconds: float = 40.0):  # type: ignore[no-untyped-def]
        import json

        from tests._pcap import DLT_EN10MB, esp_payload, eth_frame, ipv4_packet, write_pcap

        directory = root / name
        directory.mkdir(parents=True)
        frames = []
        ts = 0.0
        index = 1
        while ts < seconds:
            frames.append(
                eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(1, index, b"X" * 96)))
            )
            frames.append(
                eth_frame(ipv4_packet("10.0.0.2", "10.0.0.1", 50, esp_payload(2, index, b"X" * 96)))
            )
            index += 1
            ts += 0.1
        # 0.05 s apart: 20 packets per second, so a 10-second window clears
        # LLD section 7.6's 20-packet floor comfortably.
        write_pcap(directory / "capture.pcap", DLT_EN10MB, frames, interval_s=0.05)
        (directory / "labels.json").write_text(
            json.dumps({"expected": {"traffic_class": traffic_class}}), encoding="utf-8"
        )
        return directory

    def test_it_reads_every_session(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        from analyzer.track_b.windows import load_dataset

        self._session(tmp_path, "cfg-a", "voip")
        self._session(tmp_path, "cfg-b", "web")

        windows = load_dataset(tmp_path)

        assert {w.session_name for w in windows} == {"cfg-a", "cfg-b"}
        assert {w.traffic_class for w in windows} == {"voip", "web"}

    def test_a_session_missing_its_capture_is_skipped_not_fatal(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """An eight-hour batch that produced one broken session should still
        yield a dataset, and the count reported at the end is the honest one."""
        from analyzer.track_b.windows import load_dataset

        self._session(tmp_path, "cfg-a", "voip")
        (tmp_path / "cfg-broken").mkdir()

        assert {w.session_name for w in load_dataset(tmp_path)} == {"cfg-a"}

    def test_a_session_with_no_traffic_class_is_skipped(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """Rather than defaulting to a class, which would be a fabricated label
        in the one file that is supposed to be ground truth."""
        import json

        from analyzer.track_b.windows import load_dataset

        directory = self._session(tmp_path, "cfg-a", "voip")
        (directory / "labels.json").write_text(json.dumps({"expected": {}}), encoding="utf-8")

        assert load_dataset(tmp_path) == []

    def test_repeat_runs_are_attributed_to_their_configuration(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        from analyzer.track_b.windows import load_dataset

        self._session(tmp_path, "cfg-a", "voip")
        self._session(tmp_path, "cfg-a-r2", "voip")

        windows = load_dataset(tmp_path)

        assert {w.config_name for w in windows} == {"cfg-a"}
        assert {w.session_name for w in windows} == {"cfg-a", "cfg-a-r2"}

"""Steps 9.6-9.10: the models themselves, their ordering, and attribution.

These train real models on small synthetic datasets. That is deliberate: a test
that mocks LightGBM proves the call signature and nothing about whether the
pipeline produces a model that can classify anything, and the failure mode this
project keeps hitting is code that runs cleanly while measuring nothing.

The datasets here are separable by construction, so the accuracy assertions are
weak on purpose -- they check the pipeline learns *something*, not that it hits
PRD section 8.4's targets. Those targets are measured on the real dataset by
``track_b/train.py`` and recorded in ``models/metrics.json``; asserting them
here against synthetic data would be asserting that the synthetic data is easy.
"""

from __future__ import annotations

import numpy as np
import pytest

from analyzer.ingest.flow import Flow, SAPair
from analyzer.ingest.reader import FlowKey, PacketRecord
from analyzer.track_b.attribution import TOP_FEATURES, lightgbm_attribution
from analyzer.track_b.mode import (
    MODE_LABELS,
    ModeFeatures,
    evaluate_mode,
    extract_mode_features,
    train_mode,
)
from analyzer.track_b.traffic_clf import Matrices, evaluate, train_lightgbm

LABELS = ("email", "icmp", "video", "voip", "web")
FEATURES = ["pps", "mean_len", "iat_cv", "up_down_ratio"]


def _separable(n_per_class: int = 60, seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
    """A dataset where each class sits around its own centre."""
    rng = np.random.default_rng(seed)
    centres = np.array(
        [
            [10.0, 1200.0, 0.9, 0.2],
            [5.0, 100.0, 0.05, 1.0],
            [200.0, 1100.0, 0.2, 8.0],
            [50.0, 172.0, 0.02, 1.0],
            [30.0, 700.0, 1.5, 0.4],
        ]
    )
    rows = []
    y = []
    for index, centre in enumerate(centres):
        rows.append(rng.normal(centre, np.abs(centre) * 0.05 + 0.01, size=(n_per_class, 4)))
        y.extend([index] * n_per_class)
    return np.vstack(rows).astype(np.float32), np.array(y, dtype=np.int64)


def _matrices(x: np.ndarray, y: np.ndarray) -> Matrices:
    return Matrices(
        tabular=x,
        sequence=np.zeros((len(y), 128), dtype=np.float32),
        y=y,
        config_names=tuple(f"cfg-{i}" for i in range(len(y))),
    )


class TestLightGbmBaseline:
    def test_it_learns_a_separable_dataset(self) -> None:
        x, y = _separable()
        x_test, y_test = _separable(n_per_class=20, seed=1)

        model = train_lightgbm(
            _matrices(x, y), None, feature_names=FEATURES, labels=LABELS, num_boost_round=60
        )
        evaluation = evaluate(y_test, model.predict_proba(x_test).argmax(axis=1), LABELS)

        assert evaluation.macro_f1 > 0.8, evaluation.summary()

    def test_training_is_reproducible(self) -> None:
        """NFR-4 reaches the training pipeline too: a score that moves between
        runs is not a measurement of the model."""
        x, y = _separable()
        x_test, _ = _separable(n_per_class=20, seed=1)

        first = train_lightgbm(
            _matrices(x, y), None, feature_names=FEATURES, labels=LABELS, num_boost_round=40
        )
        second = train_lightgbm(
            _matrices(x, y), None, feature_names=FEATURES, labels=LABELS, num_boost_round=40
        )

        assert first.predict_proba(x_test) == pytest.approx(second.predict_proba(x_test))

    def test_a_saved_model_round_trips(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """The artefact has to carry its feature order and label order.

        A model reloaded without them would still predict -- into the wrong
        columns and out to the wrong class names, with no error anywhere.
        """
        from analyzer.track_b.traffic_clf import LightGbmModel

        x, y = _separable()
        model = train_lightgbm(
            _matrices(x, y), None, feature_names=FEATURES, labels=LABELS, num_boost_round=30
        )
        path = tmp_path / "traffic_lightgbm.txt"
        model.save(path)

        reloaded = LightGbmModel.load(path)

        assert reloaded.feature_names == FEATURES
        assert reloaded.labels == LABELS
        assert reloaded.predict_proba(x[:5]) == pytest.approx(model.predict_proba(x[:5]))


class TestAttribution:
    def test_a_prediction_returns_its_top_five_features(self) -> None:
        """Step 9.10's stated acceptance condition."""
        x, y = _separable()
        model = train_lightgbm(
            _matrices(x, y), None, feature_names=FEATURES, labels=LABELS, num_boost_round=40
        )
        row = x[0]
        index = int(model.predict_proba(row.reshape(1, -1))[0].argmax())

        attributions = lightgbm_attribution(model, row, class_index=index)

        assert len(attributions) == min(TOP_FEATURES, len(FEATURES))
        assert {a.feature for a in attributions} <= set(FEATURES)

    def test_attributions_are_ranked_by_magnitude(self) -> None:
        x, y = _separable()
        model = train_lightgbm(
            _matrices(x, y), None, feature_names=FEATURES, labels=LABELS, num_boost_round=40
        )
        row = x[0]
        index = int(model.predict_proba(row.reshape(1, -1))[0].argmax())

        contributions = [
            abs(a.contribution) for a in lightgbm_attribution(model, row, class_index=index)
        ]

        assert contributions == sorted(contributions, reverse=True)

    def test_attribution_reports_the_observed_value(self) -> None:
        """ "Why" needs the measurement, not only its weight."""
        x, y = _separable()
        model = train_lightgbm(
            _matrices(x, y), None, feature_names=FEATURES, labels=LABELS, num_boost_round=40
        )
        row = x[0]
        index = int(model.predict_proba(row.reshape(1, -1))[0].argmax())

        for attribution in lightgbm_attribution(model, row, class_index=index):
            expected = float(row[FEATURES.index(attribution.feature)])
            assert attribution.observed_value == pytest.approx(expected, rel=1e-5)


# ===========================================================================
# Step 9.9: the mode classifier and its ordering dependency
# ===========================================================================


def _pair(*, lengths: list[int], src: str = "10.0.0.1", dst: str = "10.0.0.2") -> SAPair:
    packets = tuple(
        PacketRecord(
            index=i,
            ts=float(i) * 0.01,
            ip_version=4,
            src=src,
            dst=dst,
            proto="esp",
            spi=1,
            seq=i,
            ip_payload_len=length + 8,
            esp_payload_len=length,
            captured_len=length + 28,
            orig_len=length + 28,
        )
        for i, length in enumerate(lengths)
    )
    return SAPair(
        forward=Flow(
            key=FlowKey(src, dst, 1, "esp"),
            packets=packets,
            start_ts=packets[0].ts,
            end_ts=packets[-1].ts,
        ),
        reverse=None,
        paired=False,
    )


class TestModeFeatures:
    def test_tunnel_mode_shows_a_larger_max_length(self) -> None:
        """LLD section 7.3, feature 1: the inner IP header is 20 bytes of
        outer packet that transport mode does not carry."""
        transport = extract_mode_features(
            _pair(lengths=[1400] * 40), list(_pair(lengths=[1400] * 40).forward.packets), {}
        )
        tunnel = extract_mode_features(
            _pair(lengths=[1420] * 40), list(_pair(lengths=[1420] * 40).forward.packets), {}
        )

        assert tunnel.max_len_over_mtu > transport.max_len_over_mtu

    def test_the_traffic_class_distribution_shifts_the_offset(self) -> None:
        """Feature 4, and the reason the ordering dependency exists at all.

        The same packets read as VoIP and as video produce different offsets,
        because the offset is measured against what that class should look like.
        """
        pair = _pair(lengths=[200] * 40)
        packets = list(pair.forward.packets)

        as_voip = extract_mode_features(pair, packets, {"voip": 1.0})
        as_video = extract_mode_features(pair, packets, {"video": 1.0})

        assert as_voip.modal_len_offset != as_video.modal_len_offset

    def test_an_uncertain_classification_blurs_the_baseline(self) -> None:
        """A 50/50 distribution must not be read as either class outright."""
        pair = _pair(lengths=[200] * 40)
        packets = list(pair.forward.packets)

        blurred = extract_mode_features(pair, packets, {"voip": 0.5, "video": 0.5})
        confident = extract_mode_features(pair, packets, {"voip": 1.0})

        assert blurred.modal_len_offset != confident.modal_len_offset

    def test_features_have_no_nans_on_a_single_packet_flow(self) -> None:
        pair = _pair(lengths=[100])
        features = extract_mode_features(pair, list(pair.forward.packets), {"icmp": 1.0})

        assert all(np.isfinite(value) for value in features.vector())

    def test_the_modal_length_is_deterministic_under_ties(self) -> None:
        """The non-determinism that broke ``esp_len_modal`` in step 9.1: when
        every length is distinct, every value is a mode."""
        pair = _pair(lengths=[100, 200, 300, 400])
        packets = list(pair.forward.packets)

        first = extract_mode_features(pair, packets, {"icmp": 1.0})
        second = extract_mode_features(pair, packets, {"icmp": 1.0})

        assert first.modal_len_offset == second.modal_len_offset


class TestModeClassifier:
    def _dataset(self, n: int = 80, seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
        rng = np.random.default_rng(seed)
        transport = rng.normal([0.90, 1.2, 0.15, -5.0], 0.03, size=(n, 4))
        tunnel = rng.normal([0.95, 6.0, 0.01, 20.0], 0.03, size=(n, 4))
        x = np.vstack([transport, tunnel]).astype(np.float32)
        y = np.array([0] * n + [1] * n, dtype=np.int64)
        return x, y

    def test_it_separates_tunnel_from_transport(self) -> None:
        x, y = self._dataset()
        x_test, y_test = self._dataset(n=30, seed=1)

        model = train_mode(x, y, num_boost_round=60)
        evaluation = evaluate_mode(model, x_test, y_test)

        assert evaluation.accuracy > 0.9, evaluation.summary()

    def test_tunnel_is_index_one(self) -> None:
        """The saved label order is part of the artefact's contract: swapping it
        would invert every prediction with nothing failing."""
        assert MODE_LABELS == ("transport", "tunnel")
        assert MODE_LABELS.index("tunnel") == 1

    def test_predict_returns_a_label_and_a_probability(self) -> None:
        x, y = self._dataset()
        model = train_mode(x, y, num_boost_round=40)

        label, confidence = model.predict(
            ModeFeatures(
                max_len_over_mtu=0.95,
                spi_pairs_per_endpoint=6.0,
                cleartext_ratio=0.01,
                modal_len_offset=20.0,
            )
        )

        assert label in MODE_LABELS
        assert 0.0 <= confidence <= 1.0

    def test_feature_names_match_the_vector_order(self) -> None:
        """A name list that drifted from the vector order would mislabel every
        SHAP explanation the mode classifier produces."""
        features = ModeFeatures(
            max_len_over_mtu=1.0,
            spi_pairs_per_endpoint=2.0,
            cleartext_ratio=3.0,
            modal_len_offset=4.0,
        )

        assert dict(zip(ModeFeatures.names(), features.vector(), strict=True)) == {
            "max_len_over_mtu": 1.0,
            "spi_pairs_per_endpoint": 2.0,
            "cleartext_ratio": 3.0,
            "modal_len_offset": 4.0,
        }


# ===========================================================================
# Step 9.11: the service loads real artefacts and predicts through them
# ===========================================================================


class TestInferenceService:
    """Step 9.11's Done when, minus the API: a real artefact, loaded from disk
    by the same code the pipeline uses, producing real ``Attribute`` objects.

    Trained here rather than fixtured because the artefact's contract includes
    its feature *order*, and a hand-written fixture would encode whatever order
    the author assumed rather than the one the extractor actually produces.
    """

    def _train_into(self, models_dir):  # type: ignore[no-untyped-def]
        import json

        from analyzer.track_b.calibration import fit_isotonic
        from analyzer.track_b.traffic_clf import label_vocabulary, matrices_for, train_lightgbm
        from analyzer.track_b.windows import (
            feature_columns,
            sequence_columns,
            split_configs,
            to_frame,
            windows_for_session,
        )

        # Two classes with plainly different rates, enough configurations for
        # the stratified split to fill all three folds.
        windows = []
        for index in range(6):
            for traffic_class, rate, length in (("voip", 50.0, 172), ("file_transfer", 5.0, 1300)):
                packets = []
                step = 1.0 / rate
                ts = 0.0
                i = 0
                while ts < 30.0:
                    packets.append(_packet_at(i, ts, 1, length))
                    packets.append(_packet_at(i + 1, ts + step / 2, 2, length))
                    i += 2
                    ts += step
                windows.extend(
                    windows_for_session(
                        packets,
                        config_name=f"cfg-{traffic_class}-{index}",
                        session_name=f"cfg-{traffic_class}-{index}",
                        traffic_class=traffic_class,
                    )
                )

        frame = to_frame(windows, split_configs(windows))
        labels = label_vocabulary(frame)
        features = feature_columns(frame)
        train = matrices_for(
            frame,
            "train",
            feature_names=features,
            sequence_names=sequence_columns(frame),
            labels=labels,
        )
        model = train_lightgbm(
            train, None, feature_names=features, labels=labels, num_boost_round=40
        )
        model.save(models_dir / "traffic_lightgbm.txt")

        isotonic = fit_isotonic(model.predict_proba(train.tabular), train.y, len(labels))
        (models_dir / "calibration.json").write_text(
            json.dumps({"cnn_temperature": 1.0, "lightgbm_isotonic_knots": isotonic.knots()}),
            encoding="utf-8",
        )
        return labels

    def test_a_loaded_model_produces_traffic_predictions(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        from analyzer.track_b.service import InferenceService

        self._train_into(tmp_path)
        service = InferenceService(tmp_path)

        predictions = service.predict_traffic(_steady_pair(rate=50.0, length=172))

        assert predictions, "a loaded classifier must actually classify"
        assert all(0.0 <= p.probability <= 1.0 for p in predictions)
        assert all(p.window_end >= p.window_start for p in predictions)

    def test_predictions_carry_their_attribution(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """FR-4.10: an inference that costs the deployment points has to be
        arguable."""
        from analyzer.track_b.service import InferenceService

        self._train_into(tmp_path)
        service = InferenceService(tmp_path)

        prediction = service.predict_traffic(_steady_pair(rate=50.0, length=172))[0]

        assert prediction.top_features
        assert len(prediction.top_features) <= TOP_FEATURES

    def test_model_versions_identify_the_artefact(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        from analyzer.track_b.service import InferenceService

        self._train_into(tmp_path)

        versions = InferenceService(tmp_path).model_versions

        assert "traffic_classifier" in versions
        assert versions["traffic_classifier"].startswith("sha256:")

    def test_an_empty_model_dir_stays_honest(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """The permanent state for a deployment shipped the code and not the
        artefacts. Not an error, and not a guess."""
        from analyzer.core.enums import Provenance
        from analyzer.core.schema import CaptureQuality
        from analyzer.track_b.service import NO_MODEL_NOTE, InferenceService

        service = InferenceService(tmp_path)
        result = service.analyse(
            _steady_pair(rate=50.0, length=172),
            CaptureQuality(
                packet_count=100,
                duration_s=30.0,
                truncated=False,
                has_ike=False,
                ike_complete=False,
                esp_sa_count=1,
                sufficient_for_lattice=False,
            ),
        )

        assert result.inner_traffic == []
        assert result.operating_mode.provenance is Provenance.UNAVAILABLE
        assert result.operating_mode.note == NO_MODEL_NOTE
        assert service.model_versions == {}

    def test_an_unreadable_artefact_is_treated_as_absent(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """A model that will not load is exactly as informative as no model, and
        crashing over it would lose the Track A analysis too."""
        from analyzer.track_b.service import InferenceService

        (tmp_path / "traffic_lightgbm.txt").write_text("not a lightgbm model", encoding="utf-8")

        service = InferenceService(tmp_path)

        assert service.predict_traffic(_steady_pair(rate=50.0, length=172)) == []
        assert "traffic_classifier" not in service.model_versions


def _packet_at(index: int, ts: float, spi: int, length: int) -> PacketRecord:
    src, dst = ("10.0.0.1", "10.0.0.2") if spi == 1 else ("10.0.0.2", "10.0.0.1")
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


def _steady_pair(*, rate: float, length: int, seconds: float = 30.0) -> SAPair:
    forward = []
    reverse = []
    step = 1.0 / rate
    ts = 0.0
    index = 0
    while ts < seconds:
        forward.append(_packet_at(index, ts, 1, length))
        reverse.append(_packet_at(index + 1, ts + step / 2, 2, length))
        index += 2
        ts += step
    return SAPair(
        forward=Flow(
            key=FlowKey("10.0.0.1", "10.0.0.2", 1, "esp"),
            packets=tuple(forward),
            start_ts=forward[0].ts,
            end_ts=forward[-1].ts,
        ),
        reverse=Flow(
            key=FlowKey("10.0.0.2", "10.0.0.1", 2, "esp"),
            packets=tuple(reverse),
            start_ts=reverse[0].ts,
            end_ts=reverse[-1].ts,
        ),
        paired=True,
    )

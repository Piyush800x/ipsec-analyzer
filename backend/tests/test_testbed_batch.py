"""Batch manifest and resume logic. Implementation-plan step 2.10.

The resume decision is tested here without Docker, because it is a decision
about files and not about containers. The end-to-end claim -- that killing a
batch midway and restarting really does skip what completed -- is in
``test_testbed_docker.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from analyzer.core.enums import OperatingMode, TrafficClass
from testbed.batch import MANIFEST_NAME, Manifest, run_batch
from testbed.config import EspSuite, IkeFlavour, SessionConfig
from testbed.orchestrator import LABELS_NAME, PCAP_NAME
from testbed.peers import TestbedError


async def _noop() -> None:
    """Stands in for preflight, which needs a Docker daemon."""


async def _no_orphans(session: str | None = None) -> tuple[int, int]:
    """Stands in for prune_orphans, which needs a Docker daemon.

    Takes *session* because the real one does: a batch cleaning up after a
    failure names the session it is cleaning up after, so that a concurrent
    shard's live containers are not swept away with it.
    """
    del session
    return 0, 0


def a_config(name: str = "session-1") -> SessionConfig:
    return SessionConfig(
        name=name,
        mode=OperatingMode.TUNNEL,
        ike=IkeFlavour.IKEV2,
        esp=EspSuite.AES128_SHA1,
        dh=14,
        pfs=True,
        traffic=TrafficClass.ICMP,
    )


def write_outputs(output_dir: Path, name: str) -> None:
    session = output_dir / name
    session.mkdir(parents=True, exist_ok=True)
    (session / PCAP_NAME).write_bytes(b"\xd4\xc3\xb2\xa1")
    (session / LABELS_NAME).write_text("{}", encoding="utf-8")


class TestResumeDecision:
    def test_an_unrun_session_is_not_complete(self, tmp_path: Path) -> None:
        assert not Manifest.load_or_create(tmp_path).is_complete(a_config(), tmp_path)

    def test_a_recorded_session_with_its_files_is_complete(self, tmp_path: Path) -> None:
        manifest = Manifest.load_or_create(tmp_path)
        write_outputs(tmp_path, "session-1")
        manifest.record_success("session-1", packet_count=100, duration_s=12.0)
        assert manifest.is_complete(a_config(), tmp_path)

    def test_a_recorded_session_whose_files_are_gone_is_not_complete(self, tmp_path: Path) -> None:
        """A manifest can outlive the files it describes -- someone clears a
        directory, a disk fills. Trusting it alone produces a dataset with holes
        that nothing reports.
        """
        manifest = Manifest.load_or_create(tmp_path)
        write_outputs(tmp_path, "session-1")
        manifest.record_success("session-1", packet_count=100, duration_s=12.0)
        (tmp_path / "session-1" / PCAP_NAME).unlink()
        assert not manifest.is_complete(a_config(), tmp_path)

    def test_a_failed_session_is_retried(self, tmp_path: Path) -> None:
        manifest = Manifest.load_or_create(tmp_path)
        write_outputs(tmp_path, "session-1")
        manifest.record_failure("session-1", RuntimeError("no SA"))
        assert not manifest.is_complete(a_config(), tmp_path)


class TestManifestPersistence:
    def test_manifest_survives_a_reload(self, tmp_path: Path) -> None:
        manifest = Manifest.load_or_create(tmp_path)
        manifest.record_success("a", packet_count=5, duration_s=1.0)
        manifest.record_failure("b", RuntimeError("boom"))

        reloaded = Manifest.load_or_create(tmp_path)
        assert reloaded.sessions["a"]["status"] == "completed"
        assert reloaded.sessions["b"]["status"] == "failed"
        assert reloaded.started_at == manifest.started_at

    def test_manifest_is_written_after_every_session(self, tmp_path: Path) -> None:
        """A batch killed between sessions must leave a manifest describing
        everything up to that point."""
        manifest = Manifest.load_or_create(tmp_path)
        manifest.record_success("a", packet_count=5, duration_s=1.0)
        on_disk = json.loads((tmp_path / MANIFEST_NAME).read_text(encoding="utf-8"))
        assert "a" in on_disk["sessions"]

    def test_attempts_accumulate_across_retries(self, tmp_path: Path) -> None:
        manifest = Manifest.load_or_create(tmp_path)
        manifest.record_failure("a", RuntimeError("first"))
        manifest.record_failure("a", RuntimeError("second"))
        manifest.record_success("a", packet_count=1, duration_s=1.0)
        assert manifest.sessions["a"]["attempts"] == 3

    def test_error_text_is_truncated(self, tmp_path: Path) -> None:
        """A strongSwan failure carries a full charon log; two hundred of them
        make the manifest unreadable."""
        manifest = Manifest.load_or_create(tmp_path)
        manifest.record_failure("a", RuntimeError("x" * 10_000))
        assert len(manifest.sessions["a"]["error"]) <= 2000

    def test_no_temporary_file_is_left_behind(self, tmp_path: Path) -> None:
        """The manifest is written to a sibling and moved into place, so a
        process killed mid-write leaves the previous one intact."""
        manifest = Manifest.load_or_create(tmp_path)
        manifest.record_success("a", packet_count=1, duration_s=1.0)
        assert not list(tmp_path.glob("*.tmp"))


class TestFailureHandling:
    """A failure must be recorded and the batch must carry on.

    Exercised with a stubbed ``run_session`` rather than a deliberately broken
    tunnel: both peers render from one config, so there is no configuration that
    reliably fails to negotiate, and a test that depends on a race is worse than
    no test.
    """

    async def test_a_failing_session_does_not_stop_the_batch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempted: list[str] = []

        async def fake_run_session(cfg: SessionConfig, output_dir: Path, **_: object) -> object:
            attempted.append(cfg.name)
            if cfg.name == "bad":
                raise TestbedError("no CHILD_SA reached INSTALLED")
            write_outputs(output_dir, cfg.name)
            return SimpleNamespace(packet_count=42, duration_s=1.0)

        monkeypatch.setattr("testbed.batch.run_session", fake_run_session)
        monkeypatch.setattr("testbed.batch.preflight", _noop)
        monkeypatch.setattr("testbed.batch.prune_orphans", _no_orphans)

        report = await run_batch(
            [a_config("good-1"), a_config("bad"), a_config("good-2")], tmp_path
        )

        assert attempted == ["good-1", "bad", "good-2"], "the batch stopped at the failure"
        assert report.completed == ["good-1", "good-2"]
        assert report.failed == ["bad"]
        assert not report.ok

    async def test_a_failed_session_is_retried_on_the_next_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Resume skips what succeeded, not what failed."""
        calls: list[str] = []

        async def fake_run_session(cfg: SessionConfig, output_dir: Path, **_: object) -> object:
            calls.append(cfg.name)
            write_outputs(output_dir, cfg.name)
            return SimpleNamespace(packet_count=1, duration_s=1.0)

        manifest = Manifest.load_or_create(tmp_path)
        manifest.record_failure("session-1", TestbedError("earlier failure"))

        monkeypatch.setattr("testbed.batch.run_session", fake_run_session)
        monkeypatch.setattr("testbed.batch.preflight", _noop)
        monkeypatch.setattr("testbed.batch.prune_orphans", _no_orphans)

        report = await run_batch([a_config()], tmp_path)
        assert calls == ["session-1"]
        assert report.completed == ["session-1"]

    async def test_stop_on_error_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def always_fails(cfg: SessionConfig, output_dir: Path, **_: object) -> object:
            raise TestbedError("nope")

        monkeypatch.setattr("testbed.batch.run_session", always_fails)
        monkeypatch.setattr("testbed.batch.preflight", _noop)
        monkeypatch.setattr("testbed.batch.prune_orphans", _no_orphans)

        with pytest.raises(TestbedError, match="nope"):
            await run_batch([a_config()], tmp_path, stop_on_error=True)

        # The failure is still recorded, so a resume knows it was attempted.
        assert Manifest.load_or_create(tmp_path).sessions["session-1"]["status"] == "failed"

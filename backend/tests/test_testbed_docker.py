"""The Phase 2 claims that only a running Docker daemon can settle.

Every test here corresponds to a **Done when** line in the implementation plan.
They are marked ``docker`` and skip on a host without a daemon, a kernel with
XFRM, or the peer image built; ``REQUIRE_TESTBED=1`` turns those skips into
failures for CI.

The multi-minute ones -- the twenty-iteration leak check and the batch resume --
are additionally gated behind ``TESTBED_SLOW=1``. They are the honest
demonstration of steps 2.3 and 2.10 and they are slow enough that running them
on every invocation would train people out of running the suite at all.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from analyzer.core.enums import OperatingMode, TrafficClass
from testbed.batch import Manifest, run_batch
from testbed.capture import start_tcpdump
from testbed.config import (
    HARDENED_REFERENCE,
    WEAK_REFERENCE,
    EspSuite,
    IkeFlavour,
    SessionConfig,
)
from testbed.orchestrator import LABELS_NAME, PCAP_NAME, run_session
from testbed.peers import TestbedError, peer_pair, preflight, prune_orphans
from testbed.tunnel import assert_sa_established, bring_up_tunnel, load_config, wait_for_charon

pytestmark = pytest.mark.docker


def quick(name: str, **overrides: object) -> SessionConfig:
    """A short session, so a test that only needs a tunnel does not wait 180s."""
    base = {
        "name": name,
        "mode": OperatingMode.TUNNEL,
        "ike": IkeFlavour.IKEV2,
        "esp": EspSuite.AES128_SHA1,
        "dh": 14,
        "pfs": True,
        "traffic": TrafficClass.ICMP,
        "duration_s": 5,
        "lifetime_s": 3600,
    }
    # mypy cannot narrow a dict[str, object] back to the field types; pydantic
    # validates every one of them at construction, which is the real check.
    return SessionConfig(**(base | overrides))  # type: ignore[arg-type]


class TestPeerImage:
    """Step 2.1: the image builds and swanctl runs inside it."""

    async def test_swanctl_runs_inside_the_image(self, testbed_available: None) -> None:
        """swanctl connects to vici at startup, so this is only meaningful with
        charon actually running -- which is also the only state it is used in.
        """
        async with peer_pair(quick("image-check")) as (left, _):
            await wait_for_charon(left)
            _, output = await left.exec(["swanctl", "--version"])
            assert "strongSwan" in output

    async def test_kernel_libipsec_is_absent(self, testbed_available: None) -> None:
        """LLD 10.3. Userspace ESP does not reproduce the kernel's padding, IV
        placement or MTU behaviour, and Track B's entire feature set is packet
        geometry. A dataset generated over libipsec would be worse than none.
        """
        async with peer_pair(quick("libipsec-check")) as (left, _):
            code, _ = await left.exec(
                ["test", "-e", "/usr/lib/ipsec/plugins/libstrongswan-kernel-libipsec.so"],
                check=False,
            )
            assert code != 0, "kernel-libipsec is present in the peer image"

            log = await left.logs(tail=200)
            assert "kernel-netlink" in log, "charon is not using the kernel XFRM interface"

    async def test_image_records_its_build_provenance(self, testbed_available: None) -> None:
        async with peer_pair(quick("versions-check")) as (left, _):
            _, output = await left.exec(["cat", "/etc/testbed-versions.json"])
            versions = json.loads(output)
            assert versions["strongswan-swanctl"].startswith("5.9.8")
            assert versions["tcpdump"]

    async def test_preflight_passes_on_a_usable_host(self, testbed_available: None) -> None:
        await preflight()


class TestConfigLoads:
    """Step 2.2: both reference fixtures load into strongSwan without error."""

    @pytest.mark.parametrize(
        "reference", [WEAK_REFERENCE, HARDENED_REFERENCE], ids=["weak", "hardened"]
    )
    async def test_reference_config_loads(
        self, testbed_available: None, reference: SessionConfig
    ) -> None:
        cfg = reference.model_copy(update={"duration_s": 5})
        async with peer_pair(cfg) as (left, _):
            await wait_for_charon(left)
            await load_config(left, cfg)
            _, listing = await left.exec(["swanctl", "--list-conns"])
            assert "testbed" in listing

    async def test_a_config_strongswan_rejects_raises(self, testbed_available: None) -> None:
        """A discarded connection must raise here, not at the next step.

        Otherwise the daemon runs on with no connections loaded and the failure
        surfaces as "CHILD_SA config not found", which sends you looking in the
        wrong place entirely.
        """
        cfg = quick("bad-proposal")
        async with peer_pair(cfg) as (left, _):
            await wait_for_charon(left)
            await left.write_file(
                "/etc/swanctl/swanctl.conf",
                "connections {\n  testbed {\n    version = 2\n"
                "    proposals = not-a-real-algorithm\n  }\n}\n",
            )
            code, output = await left.exec(["swanctl", "--load-all"], check=False)
            assert code != 0 or "loaded 0 of" in output

        # Note that reaching this state through `load_config` is not possible:
        # SessionConfig validates the DH group and the PSK, and the template
        # renders everything else from enum members. That is the intent -- an
        # unloadable configuration should be unrepresentable rather than merely
        # detected -- so the detection is exercised on a hand-written file.


class TestTunnelGuard:
    """Step 2.4: a broken config fails fast, with a message that explains it."""

    async def test_mismatched_psk_fails_fast(self, testbed_available: None) -> None:
        """LLD 10.2 calls this guard non-negotiable. Without it, a failed
        negotiation yields a capture full of IKE retries carrying a label that
        says it is a working tunnel -- a poisoned row that is very hard to find
        later.
        """
        cfg = quick("psk-mismatch")
        mismatched = cfg.model_copy(update={"psk": "a-completely-different-psk"})
        async with peer_pair(cfg) as (left, right):
            with pytest.raises(TestbedError) as raised:
                await bring_up_tunnel(left, right, cfg, responder_cfg=mismatched)

            message = str(raised.value)
            assert "failed to establish" in message
            # The proposals and mode are named, so the reader can tell a PSK
            # mismatch from an algorithm mismatch without opening a terminal,
            # and the responder log is attached because the initiator only ever
            # sees AUTHENTICATION_FAILED.
            assert cfg.ike_proposal in message
            assert "responder log" in message

    async def test_a_failed_negotiation_leaves_no_established_sa(
        self, testbed_available: None
    ) -> None:
        """The guard must not be satisfiable by a half-open SA."""
        cfg = quick("psk-mismatch-state")
        mismatched = cfg.model_copy(update={"psk": "another-different-psk"})
        async with peer_pair(cfg) as (left, right):
            with pytest.raises(TestbedError):
                await bring_up_tunnel(left, right, cfg, responder_cfg=mismatched)
            with pytest.raises(TestbedError, match="ESTABLISHED"):
                await assert_sa_established(left, timeout_s=3)

    async def test_assert_sa_established_raises_when_nothing_is_up(
        self, testbed_available: None
    ) -> None:
        cfg = quick("no-sa")
        async with peer_pair(cfg) as (left, _):
            await wait_for_charon(left)
            await load_config(left, cfg)
            with pytest.raises(TestbedError, match="ESTABLISHED"):
                await assert_sa_established(left, timeout_s=3)


class TestCapture:
    """Step 2.5: the capture contains both IKE and ESP."""

    async def test_capture_contains_ike_and_esp(
        self, testbed_available: None, tmp_path: Path
    ) -> None:
        cfg = quick("capture-check")
        dest = tmp_path / "capture.pcap"
        async with peer_pair(cfg) as (left, right):
            capture = await start_tcpdump(left, dest)
            await bring_up_tunnel(left, right, cfg)
            await assert_sa_established(left)
            await left.exec(
                ["ping", "-c", "5", "-I", left.traffic_addr, right.traffic_addr], check=False
            )
            await asyncio.sleep(2)
            _, listing = await left.exec(
                [
                    "sh",
                    "-c",
                    f"tcpdump -r {capture.container_path} -n 2>/dev/null",
                ]
            )
            await capture.stop()

        assert dest.is_file()
        # A libpcap file, either endianness, microsecond or nanosecond.
        assert dest.read_bytes()[:4] in {
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
        }
        assert "isakmp" in listing, "no IKE in the capture"
        assert "ESP(spi=" in listing, "no ESP in the capture"

    async def test_an_empty_capture_raises(self, testbed_available: None, tmp_path: Path) -> None:
        """An empty PCAP beside a valid labels.json is worse than a failed
        session: the batch reports success and the row poisons training."""
        cfg = quick("empty-capture")
        async with peer_pair(cfg) as (left, _):
            capture = await start_tcpdump(
                left, tmp_path / "empty.pcap", capture_filter="udp port 65000"
            )
            with pytest.raises(TestbedError, match="no packets"):
                await capture.stop()


class TestSession:
    """Step 2.8: one end-to-end session, with the teardown inside the capture."""

    async def test_session_produces_capture_and_labels(
        self, testbed_available: None, tmp_path: Path
    ) -> None:
        result = await run_session(quick("full-session"), tmp_path)

        assert (tmp_path / "full-session" / PCAP_NAME).is_file()
        assert (tmp_path / "full-session" / LABELS_NAME).is_file()
        assert result.packet_count > 0

    async def test_capture_contains_the_ike_delete_exchange(
        self, testbed_available: None, tmp_path: Path
    ) -> None:
        """LLD 10.2: tear the tunnel down inside the capture window, because
        real analyst captures contain the DELETE.
        """
        result = await run_session(quick("delete-exchange"), tmp_path)
        assert result.has_ike_delete

    async def test_labels_record_what_was_actually_negotiated(
        self, testbed_available: None, tmp_path: Path
    ) -> None:
        """Configured and negotiated are recorded separately, so that if they
        ever diverge the dataset says so instead of asserting the config."""
        result = await run_session(quick("negotiated"), tmp_path)
        observed = result.labels["observed"]
        assert "AES_CBC-128" in observed["negotiated_ike"]
        assert "AES_CBC-128" in observed["negotiated_esp"]
        assert result.labels["image_versions"]["strongswan-swanctl"]


class TestTrafficGenerators:
    """Step 2.6: each class produces a visibly different profile."""

    @pytest.mark.parametrize("traffic", list(TrafficClass), ids=lambda c: c.value)
    @pytest.mark.slow
    async def test_generator_produces_traffic(
        self, testbed_slow: None, tmp_path: Path, traffic: TrafficClass
    ) -> None:
        result = await run_session(
            quick(f"traffic-{traffic.value}", traffic=traffic, duration_s=15), tmp_path
        )
        assert result.packet_count > 0, f"{traffic.value} generated nothing"


class TestNoResourceLeaks:
    """Step 2.3: twenty iterations leave zero orphaned containers or networks."""

    @pytest.mark.slow
    async def test_repeated_use_leaks_nothing(self, testbed_slow: None) -> None:
        await prune_orphans()
        for index in range(20):
            async with peer_pair(quick(f"leak-{index}")) as (left, right):
                assert left.name != right.name

        containers, networks = await prune_orphans()
        assert (containers, networks) == (0, 0), (
            f"peer_pair leaked {containers} containers and {networks} networks over 20 runs"
        )

    async def test_teardown_runs_even_when_the_body_raises(self, testbed_available: None) -> None:
        """A cleanup that only happens on the happy path is a cleanup that
        never happens during a batch, which is where failures live."""
        await prune_orphans()
        with pytest.raises(RuntimeError, match="deliberate"):
            async with peer_pair(quick("teardown-on-error")):
                raise RuntimeError("deliberate")

        containers, networks = await prune_orphans()
        assert (containers, networks) == (0, 0)


class TestBatchResume:
    """Step 2.10: a batch completes, and a restart skips what already ran."""

    @pytest.mark.slow
    async def test_batch_completes_and_resumes(self, testbed_slow: None, tmp_path: Path) -> None:
        configs = [quick(f"batch-{i:02d}", duration_s=3) for i in range(4)]

        first = await run_batch(configs[:2], tmp_path)
        assert first.ok
        assert len(first.completed) == 2

        # Restarting over the full list must re-run only what has not run,
        # which is what makes an eight-hour generation job survivable.
        second = await run_batch(configs, tmp_path)
        assert second.ok
        assert sorted(second.skipped) == [c.name for c in configs[:2]]
        assert sorted(second.completed) == [c.name for c in configs[2:]]

        manifest = Manifest.load_or_create(tmp_path)
        assert all(entry["status"] == "completed" for entry in manifest.sessions.values()), (
            manifest.sessions
        )

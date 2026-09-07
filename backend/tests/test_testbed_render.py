"""Rendering a SessionConfig into swanctl.conf. Implementation-plan step 2.2.

These assert the shape of the rendered text. That strongSwan actually *accepts*
it is a separate claim, and one only a running daemon can settle -- see
``test_testbed_docker.py::TestConfigLoads``.
"""

from __future__ import annotations

import pytest

from analyzer.core.enums import OperatingMode, TrafficClass
from testbed.config import (
    HARDENED_REFERENCE,
    REKEY_WINDOW_S,
    WEAK_REFERENCE,
    EspSuite,
    IkeFlavour,
    IpVersion,
    SessionConfig,
)
from testbed.render import CHILD_NAME, CONNECTION_NAME, peer_identity, render_swanctl_conf


def settings(rendered: str) -> dict[str, str]:
    """Every ``key = value`` in the rendered config, last occurrence winning.

    Crude on purpose: it does not model the nesting, which keeps the tests about
    values rather than about a parser written to satisfy them.
    """
    found = {}
    for line in rendered.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "=" not in stripped or stripped.endswith("{"):
            continue
        key, _, value = stripped.partition("=")
        found[key.strip()] = value.strip()
    return found


def test_one_setting_per_line() -> None:
    """strongSwan accepts `auth = psk  id = x` as a single value and then
    rejects it as "invalid value for: auth", which reads like a value problem
    rather than a layout one. It cost an afternoon once.
    """
    rendered = render_swanctl_conf(HARDENED_REFERENCE, "left")
    for line in rendered.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        assert stripped.count("=") <= 1, f"two settings on one line: {line!r}"


class TestVersionAndMode:
    def test_ikev1_renders_version_1(self) -> None:
        assert settings(render_swanctl_conf(WEAK_REFERENCE, "left"))["version"] == "1"

    def test_ikev2_renders_version_2(self) -> None:
        assert settings(render_swanctl_conf(HARDENED_REFERENCE, "left"))["version"] == "2"

    def test_aggressive_mode_only_for_ikev1_aggressive(self) -> None:
        assert settings(render_swanctl_conf(WEAK_REFERENCE, "left"))["aggressive"] == "yes"

        main = WEAK_REFERENCE.model_copy(update={"ike": IkeFlavour.IKEV1_MAIN})
        assert "aggressive" not in settings(render_swanctl_conf(main, "left"))

    def test_ikev2_never_renders_aggressive(self) -> None:
        assert "aggressive" not in settings(render_swanctl_conf(HARDENED_REFERENCE, "left"))

    @pytest.mark.parametrize("mode", list(OperatingMode))
    def test_child_mode_matches_the_config(self, mode: OperatingMode) -> None:
        cfg = HARDENED_REFERENCE.model_copy(update={"mode": mode})
        assert settings(render_swanctl_conf(cfg, "left"))["mode"] == mode.value


class TestPointOfView:
    """Both sides come from one config; only the point of view differs."""

    def test_addresses_are_mirrored(self) -> None:
        left = settings(render_swanctl_conf(HARDENED_REFERENCE, "left"))
        right = settings(render_swanctl_conf(HARDENED_REFERENCE, "right"))
        assert left["local_addrs"] == right["remote_addrs"]
        assert left["remote_addrs"] == right["local_addrs"]

    def test_traffic_selectors_are_mirrored(self) -> None:
        left = settings(render_swanctl_conf(HARDENED_REFERENCE, "left"))
        right = settings(render_swanctl_conf(HARDENED_REFERENCE, "right"))
        assert left["local_ts"] == right["remote_ts"]
        assert left["remote_ts"] == right["local_ts"]

    def test_identities_are_mirrored(self) -> None:
        rendered = render_swanctl_conf(HARDENED_REFERENCE, "left")
        assert f"id = {peer_identity('left')}" in rendered
        assert f"id = {peer_identity('right')}" in rendered

    def test_both_sides_propose_the_same_algorithms(self) -> None:
        """A mismatch here does not fail loudly. It fails as a tunnel that never
        establishes, twenty minutes into a batch run."""
        left = settings(render_swanctl_conf(HARDENED_REFERENCE, "left"))
        right = settings(render_swanctl_conf(HARDENED_REFERENCE, "right"))
        assert left["proposals"] == right["proposals"]
        assert left["esp_proposals"] == right["esp_proposals"]


class TestDeterminismControls:
    def test_rekey_jitter_is_disabled(self) -> None:
        """strongSwan jitters rekeying by up to 10% of rekey_time by default --
        exactly the tolerance step 9.3 measures against."""
        rendered = render_swanctl_conf(HARDENED_REFERENCE, "left")
        assert rendered.count("rand_time = 0s") == 2

    def test_rekey_is_time_based_only(self) -> None:
        """A byte- or packet-triggered rekey would make the observed rekey
        interval depend on the traffic class, which is the confound step 9.3
        must not have."""
        rendered = render_swanctl_conf(HARDENED_REFERENCE, "left")
        assert "rekey_bytes = 0" in rendered
        assert "rekey_packets = 0" in rendered

    def test_lifetime_is_rendered_on_both_the_ike_sa_and_the_child(self) -> None:
        cfg = HARDENED_REFERENCE.model_copy(update={"lifetime_s": 300})
        rendered = render_swanctl_conf(cfg, "left")

        # `lifetime_s` is the *hard* lifetime -- the value IKEv1 puts on the
        # wire and the one labels.json claims. strongSwan derives that as
        # rekey_time + over_time, so the rendered rekey time is the configured
        # lifetime minus the window.
        assert rendered.count(f"rekey_time = {300 - REKEY_WINDOW_S}s") == 2
        assert f"over_time = {REKEY_WINDOW_S}s" in rendered

    def test_the_rekey_window_is_never_zero(self) -> None:
        """strongSwan *deletes* an SA that has not rekeyed within
        ``rekey_time + over_time``.

        With no window the SA hard-expires at the instant it tries to rekey. A
        300-second tunnel captured for 700 seconds died at t=300 with the rekey
        exchange on the wire and nothing after it, which is how this was found.
        """
        assert REKEY_WINDOW_S > 0
        assert f"over_time = {REKEY_WINDOW_S}s" in render_swanctl_conf(HARDENED_REFERENCE, "left")

    def test_the_negotiated_lifetime_matches_what_is_configured(self) -> None:
        """rekey_time + over_time is what goes on the IKEv1 wire, and
        `labels.json` states it as `negotiated_lifetime_s`. If those two ever
        drift apart, every label disagrees with every capture -- which is
        exactly what a default over_time did (95040s for a configured 86400s).
        """
        cfg = HARDENED_REFERENCE.model_copy(update={"lifetime_s": 3600})

        assert cfg.rekey_time_s + cfg.over_time_s == cfg.lifetime_s
        assert cfg.to_ground_truth()["expected"]["negotiated_lifetime_s"] == cfg.lifetime_s

    def test_keyingtries_is_one(self) -> None:
        """A configuration that cannot negotiate must fail while the
        orchestrator is watching, not retransmit until the capture closes."""
        assert settings(render_swanctl_conf(HARDENED_REFERENCE, "left"))["keyingtries"] == "1"

    def test_child_does_not_start_itself(self) -> None:
        """Auto-start would race the capture and put IKE outside the PCAP."""
        assert settings(render_swanctl_conf(HARDENED_REFERENCE, "left"))["start_action"] == "none"


class TestSecrets:
    def test_secret_lists_both_identities_and_both_addresses(self) -> None:
        """IKEv1 main mode cannot know the peer identity until message 5, which
        is already encrypted, so the responder finds the PSK by address."""
        rendered = render_swanctl_conf(WEAK_REFERENCE, "left")
        found = settings(rendered)
        assert found["id-0"] == peer_identity("left")
        assert found["id-1"] == peer_identity("right")
        assert found["id-2"] == "10.10.0.2"
        assert found["id-3"] == "10.10.0.3"

    def test_psk_is_rendered_quoted(self) -> None:
        rendered = render_swanctl_conf(WEAK_REFERENCE, "left")
        assert f'secret = "{WEAK_REFERENCE.psk}"' in rendered


def test_connection_and_child_names_are_what_the_orchestrator_initiates() -> None:
    """tunnel.py initiates by these names without carrying the config around."""
    rendered = render_swanctl_conf(HARDENED_REFERENCE, "left")
    assert f"{CONNECTION_NAME} {{" in rendered
    assert f"{CHILD_NAME} {{" in rendered


def test_ipv6_config_renders_v6_addresses() -> None:
    cfg = SessionConfig(
        name="v6",
        mode=OperatingMode.TUNNEL,
        ike=IkeFlavour.IKEV2,
        esp=EspSuite.AES128_SHA1,
        dh=14,
        pfs=True,
        ip=IpVersion.V6,
        traffic=TrafficClass.ICMP,
    )
    found = settings(render_swanctl_conf(cfg, "left"))
    assert found["local_addrs"].startswith("fd00:")
    assert found["local_ts"].startswith("fd00:")

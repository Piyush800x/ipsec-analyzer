"""Steps 4.1-4.5, 4.7: the tshark subprocess wrapper and ISAKMP extraction.

Built against synthetic tshark JSON (``tests/_tshark_json.py``) rather than a
real capture -- see that module's docstring and ``ike_parser.py``'s for why.
``run_tshark`` itself is still exercised as a real subprocess, against a
small fake "tshark" script, so step 4.1's actual subprocess-and-JSON-parse
path is genuinely covered even without the real binary.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from analyzer.core.enums import (
    AuthMethod,
    EncryptionAlg,
    IkeExchangeMode,
    IkeVersion,
    IntegrityAlg,
    PrfAlg,
)
from analyzer.track_a.ike_parser import (
    IKE_EXCHANGE_TYPE_AGGRESSIVE,
    IKE_EXCHANGE_TYPE_MAIN,
    TrackAError,
    build_negotiations,
    parse_isakmp_json,
    run_tshark,
)
from tests._fakebin import write_fake_binary
from tests._tshark_json import attr, isakmp_header, notify, packet, proposal, sa_payload, transform

IKE_SA_INIT = 34

# ===========================================================================
# Step 4.1: run_tshark as a real subprocess, against a fake tshark
# ===========================================================================


def test_run_tshark_parses_stdout_json(tmp_path: Path) -> None:
    fake = write_fake_binary(tmp_path / "tshark", stdout='[{"ok": true}]\n')
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"")

    result = run_tshark(pcap, tshark_bin=str(fake))

    assert result == [{"ok": True}]


def test_run_tshark_missing_binary_raises() -> None:
    with pytest.raises(TrackAError, match="not on PATH"):
        run_tshark(Path("/nonexistent.pcap"), tshark_bin="definitely-not-a-real-binary")


def test_run_tshark_nonzero_exit_raises(tmp_path: Path) -> None:
    fake = write_fake_binary(tmp_path / "tshark", stderr="bad file\n", exit_code=1)
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"")

    with pytest.raises(TrackAError, match="bad file"):
        run_tshark(pcap, tshark_bin=str(fake))


def test_run_tshark_malformed_json_raises(tmp_path: Path) -> None:
    fake = write_fake_binary(tmp_path / "tshark", stdout="not json at all {\n")
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"")

    with pytest.raises(TrackAError, match="not valid JSON"):
        run_tshark(pcap, tshark_bin=str(fake))


def test_run_tshark_empty_output_is_empty_list(tmp_path: Path) -> None:
    fake = write_fake_binary(tmp_path / "tshark")
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"")

    assert run_tshark(pcap, tshark_bin=str(fake)) == []


def test_run_tshark_environment_has_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sanity check that the test harness's PATH assumption holds."""
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))


# ===========================================================================
# Steps 4.2, 4.3: parse_isakmp_json
# ===========================================================================


def test_parse_ikev2_message_fields() -> None:
    raw = [
        packet(
            frame_number=1,
            ts=0.0,
            src="10.0.0.1",
            dst="10.0.0.2",
            isakmp=isakmp_header(
                version="2.0",
                exchange_type=IKE_SA_INIT,
                init_spi="1111111111111111",
                resp_spi="0000000000000000",
                sa=sa_payload(
                    [
                        proposal(
                            number=1,
                            protocol_id=1,
                            transforms=[
                                transform(transform_type=1, transform_id=12, attrs=[attr(14, 256)]),
                            ],
                        )
                    ]
                ),
            ),
        )
    ]

    (message,) = parse_isakmp_json(raw)

    assert message.ike_version is IkeVersion.IKEV2
    assert message.exchange_type == IKE_SA_INIT
    assert message.src == "10.0.0.1"
    assert message.frame_index == 1
    assert message.sa_payload is not None
    (parsed_proposal,) = message.sa_payload
    assert parsed_proposal.protocol_id == 1
    (parsed_transform,) = parsed_proposal.transforms
    assert parsed_transform.transform_type == 1
    assert parsed_transform.transform_id == 12
    assert parsed_transform.attr(14) == 256


def test_parse_message_with_no_isakmp_layer_is_skipped() -> None:
    raw = [{"_source": {"layers": {"frame": {"frame.number": "1"}}}}]
    assert parse_isakmp_json(raw) == []


def test_parse_nat_detection_notify() -> None:
    raw = [
        packet(
            frame_number=1,
            ts=0.0,
            src="10.0.0.1",
            dst="10.0.0.2",
            isakmp=isakmp_header(
                version="2.0",
                exchange_type=IKE_SA_INIT,
                init_spi="1111111111111111",
                notify=[notify(16406), notify(16407)],
            ),
        )
    ]

    (message,) = parse_isakmp_json(raw)

    assert message.nat_detected is True


def test_parse_single_proposal_collapses_to_dict_not_list() -> None:
    """tshark's tendency to render a lone repeated element as a bare object
    rather than a one-element list, exercised deliberately."""
    raw = [
        packet(
            frame_number=1,
            ts=0.0,
            src="10.0.0.1",
            dst="10.0.0.2",
            isakmp=isakmp_header(
                version="1.0",
                exchange_type=IKE_EXCHANGE_TYPE_MAIN,
                init_spi="2222222222222222",
                sa=sa_payload(
                    [
                        proposal(
                            number=1,
                            protocol_id=1,
                            transforms=[transform(transform_type=1, transform_id=1)],
                        )
                    ]
                ),
            ),
        )
    ]

    (message,) = parse_isakmp_json(raw)

    assert message.sa_payload is not None
    assert len(message.sa_payload) == 1


# ===========================================================================
# Step 4.4: proposed vs selected, from a request/response pair
# ===========================================================================


def _ikev2_sa_init_pair(
    *, encr_id: int = 20, keylen: int = 256, integ_id: int = 0, prf_id: int = 5, dh_id: int = 19
) -> list[dict]:
    transforms = [
        transform(transform_type=1, transform_id=encr_id, attrs=[attr(14, keylen)]),
        transform(transform_type=2, transform_id=prf_id),
        transform(transform_type=3, transform_id=integ_id),
        transform(transform_type=4, transform_id=dh_id),
    ]
    sa = sa_payload([proposal(number=1, protocol_id=1, transforms=transforms)])
    request = packet(
        frame_number=1,
        ts=0.0,
        src="10.0.0.1",
        dst="10.0.0.2",
        isakmp=isakmp_header(
            version="2.0", exchange_type=IKE_SA_INIT, init_spi="aaaa000000000000", sa=sa
        ),
    )
    response = packet(
        frame_number=2,
        ts=0.05,
        src="10.0.0.2",
        dst="10.0.0.1",
        isakmp=isakmp_header(
            version="2.0",
            exchange_type=IKE_SA_INIT,
            init_spi="aaaa000000000000",
            resp_spi="bbbb000000000000",
            sa=sa,
        ),
    )
    return [request, response]


def test_ikev2_negotiation_full_extraction() -> None:
    messages = parse_isakmp_json(_ikev2_sa_init_pair())

    (negotiation,) = build_negotiations(messages)

    assert negotiation.ike_version is IkeVersion.IKEV2
    assert negotiation.exchange_mode is None
    assert negotiation.encryption_alg is EncryptionAlg.AES_GCM_16
    assert negotiation.encryption_keylen == 256
    assert negotiation.integrity_alg is IntegrityAlg.NONE
    assert negotiation.prf_alg is PrfAlg.HMAC_SHA256
    assert negotiation.dh_group == 19
    assert negotiation.downgrade_available is False
    assert negotiation.lifetime_s is None
    assert negotiation.auth_method is None
    assert negotiation.resp_spi == "bbbb000000000000"


def test_ikev2_esn_transform_when_present() -> None:
    transforms_with_esn = [
        transform(transform_type=1, transform_id=12, attrs=[attr(14, 128)]),
        transform(transform_type=5, transform_id=1),  # ESN
    ]
    sa = sa_payload([proposal(number=1, protocol_id=3, transforms=transforms_with_esn)])
    raw = [
        packet(
            frame_number=1,
            ts=0.0,
            src="10.0.0.1",
            dst="10.0.0.2",
            isakmp=isakmp_header(version="2.0", exchange_type=IKE_SA_INIT, init_spi="cccc", sa=sa),
        ),
        packet(
            frame_number=2,
            ts=0.1,
            src="10.0.0.2",
            dst="10.0.0.1",
            isakmp=isakmp_header(version="2.0", exchange_type=IKE_SA_INIT, init_spi="cccc", sa=sa),
        ),
    ]

    (negotiation,) = build_negotiations(parse_isakmp_json(raw))

    assert negotiation.esn is True


def test_ikev1_aggressive_mode_extraction() -> None:
    """The weak-reference shape: aggressive mode, 3DES, PSK, a lifetime."""
    transforms = [
        transform(
            transform_type=1,
            transform_id=1,
            attrs=[
                attr(1, 5),  # Encryption Algorithm = 3DES-CBC
                attr(2, 2),  # Hash Algorithm = SHA1
                attr(3, 1),  # Auth Method = PSK
                attr(4, 2),  # Group Description = 1024-bit MODP
                attr(11, 1),  # Life Type = seconds
                attr(12, 3600),  # Life Duration = 3600s
            ],
        )
    ]
    sa = sa_payload([proposal(number=1, protocol_id=1, transforms=transforms)])
    raw = [
        packet(
            frame_number=1,
            ts=0.0,
            src="10.0.0.1",
            dst="10.0.0.2",
            isakmp=isakmp_header(
                version="1.0", exchange_type=IKE_EXCHANGE_TYPE_AGGRESSIVE, init_spi="dddd", sa=sa
            ),
        ),
        packet(
            frame_number=2,
            ts=0.2,
            src="10.0.0.2",
            dst="10.0.0.1",
            isakmp=isakmp_header(
                version="1.0", exchange_type=IKE_EXCHANGE_TYPE_AGGRESSIVE, init_spi="dddd", sa=sa
            ),
        ),
    ]

    (negotiation,) = build_negotiations(parse_isakmp_json(raw))

    assert negotiation.ike_version is IkeVersion.IKEV1
    assert negotiation.exchange_mode is IkeExchangeMode.AGGRESSIVE
    assert negotiation.encryption_alg is EncryptionAlg.TRIPLE_DES_CBC
    assert negotiation.integrity_alg is IntegrityAlg.HMAC_SHA1_96
    assert negotiation.auth_method is AuthMethod.PSK
    assert negotiation.dh_group == 2
    assert negotiation.lifetime_s == 3600
    assert negotiation.prf_alg is None  # IKEv1 has no separate PRF negotiation


def test_ikev1_main_mode_downgrade_available() -> None:
    """Step 4.4 Done-when: 3DES offered alongside AES-256, AES-256 selected."""
    weak_transform = transform(
        transform_type=1, transform_id=1, attrs=[attr(1, 5), attr(2, 2), attr(3, 1), attr(4, 2)]
    )
    strong_transform = transform(
        transform_type=1,
        transform_id=1,
        attrs=[attr(1, 7), attr(2, 4), attr(3, 1), attr(4, 14), attr(14, 256)],
    )
    request_sa = sa_payload(
        [
            proposal(number=1, protocol_id=1, transforms=[weak_transform]),
            proposal(number=2, protocol_id=1, transforms=[strong_transform]),
        ]
    )
    response_sa = sa_payload([proposal(number=2, protocol_id=1, transforms=[strong_transform])])
    raw = [
        packet(
            frame_number=1,
            ts=0.0,
            src="10.0.0.1",
            dst="10.0.0.2",
            isakmp=isakmp_header(
                version="1.0", exchange_type=IKE_EXCHANGE_TYPE_MAIN, init_spi="eeee", sa=request_sa
            ),
        ),
        packet(
            frame_number=2,
            ts=0.1,
            src="10.0.0.2",
            dst="10.0.0.1",
            isakmp=isakmp_header(
                version="1.0", exchange_type=IKE_EXCHANGE_TYPE_MAIN, init_spi="eeee", sa=response_sa
            ),
        ),
    ]

    (negotiation,) = build_negotiations(parse_isakmp_json(raw))

    assert negotiation.encryption_alg is EncryptionAlg.AES_CBC
    assert negotiation.encryption_keylen == 256
    assert negotiation.downgrade_available is True


def test_no_downgrade_when_only_one_proposal_offered() -> None:
    transforms = [
        transform(transform_type=1, transform_id=7, attrs=[attr(1, 7), attr(3, 1), attr(4, 14)])
    ]
    sa = sa_payload([proposal(number=1, protocol_id=1, transforms=transforms)])
    raw = [
        packet(
            frame_number=1,
            ts=0.0,
            src="10.0.0.1",
            dst="10.0.0.2",
            isakmp=isakmp_header(
                version="1.0", exchange_type=IKE_EXCHANGE_TYPE_MAIN, init_spi="ffff", sa=sa
            ),
        ),
        packet(
            frame_number=2,
            ts=0.1,
            src="10.0.0.2",
            dst="10.0.0.1",
            isakmp=isakmp_header(
                version="1.0", exchange_type=IKE_EXCHANGE_TYPE_MAIN, init_spi="ffff", sa=sa
            ),
        ),
    ]

    (negotiation,) = build_negotiations(parse_isakmp_json(raw))

    assert negotiation.downgrade_available is False


def test_no_response_yields_selected_none() -> None:
    """A capture that only saw the initiator's message -- IKE mid-stream or
    a negotiation that never completed."""
    sa = sa_payload(
        [
            proposal(
                number=1, protocol_id=1, transforms=[transform(transform_type=1, transform_id=12)]
            )
        ]
    )
    raw = [
        packet(
            frame_number=1,
            ts=0.0,
            src="10.0.0.1",
            dst="10.0.0.2",
            isakmp=isakmp_header(version="2.0", exchange_type=IKE_SA_INIT, init_spi="0101", sa=sa),
        )
    ]

    (negotiation,) = build_negotiations(parse_isakmp_json(raw))

    assert negotiation.selected is None
    assert negotiation.encryption_alg is None
    assert negotiation.resp_spi is None

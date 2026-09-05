"""IKE SA to Child SA / ESP flow correlation (LLD 6.2). Step 4.6.

Also step 4.8: assembling the correlated result into ``SecurityAssociation``,
and ``run_track_a``, the pipeline entry point tying steps 4.1-4.8 together.
Neither has its own file in LLD section 2's tree; both belong here because
assembly *is* correlation's next step; see the module docstring notes below
for why this is a deliberate, documented departure from the plan's literal
three-file layout (also see CHANGELOG.md).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Final, TypeVar

from analyzer.core.enums import AuthMethod, EncryptionAlg, IkeExchangeMode, IkeVersion, PrfAlg
from analyzer.core.schema import Attribute, Evidence, SecurityAssociation
from analyzer.ingest.flow import Flow, SAPair
from analyzer.track_a.ike_parser import (
    IkeNegotiation,
    build_negotiations,
    parse_isakmp_json,
    run_tshark,
)

CORRELATION_WINDOW_S: Final = 30.0
"""How long after an IKE negotiation completes a Child SA's first packet may
still be attributed to it. LLD section 10.2's session lifecycle brings the
tunnel up and starts traffic within a few seconds of ``ESTABLISHED``, so this
is generous headroom, not a tuned threshold."""

_SAME_FAMILY_CONFIDENCE: Final = 0.6
"""Deliberately moderate. LLD section 6.4 calls same-family inference "the
common case", not a certainty -- and this project's own testbed proposes IKE
on CBC-plus-HMAC even when the Child SA proposal is AEAD (CHANGELOG.md,
Phase 2 deviations), which is exactly a case where this guess is wrong. A
confidence here should read as "a reasonable default assumption", not as a
calibrated estimate the way Track B's INFERRED values are."""


# ===========================================================================
# Step 4.6: correlation
# ===========================================================================


def correlate_negotiation(flow: Flow, negotiations: list[IkeNegotiation]) -> IkeNegotiation | None:
    """The IKE negotiation that most plausibly created *flow*.

    A Child SA's own SPI is proposed inside an encrypted exchange -- IKEv1
    Quick Mode, IKEv2 ``IKE_AUTH``/``CREATE_CHILD_SA`` -- so it cannot be read
    from the IKE side and matched against the ESP SPI the flow carries. This
    correlates on what *is* observable instead: the same pair of outer
    endpoints, and the negotiation completing shortly before the flow's first
    packet. When more than one negotiation qualifies (a rekey, say), the most
    recent one wins, since that is the SA actually in force when the flow
    began.
    """
    candidates = [
        negotiation
        for negotiation in negotiations
        if {negotiation.src, negotiation.dst} == {flow.key.src, flow.key.dst}
        and negotiation.ts <= flow.start_ts
        and flow.start_ts - negotiation.ts <= CORRELATION_WINDOW_S
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda n: n.ts)


# ===========================================================================
# Step 4.8: assembly into SecurityAssociation
# ===========================================================================


def _spi_hex(value: int) -> str:
    return f"{value:08x}"


def _to_utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=UTC)


def _ike_evidence(negotiation: IkeNegotiation) -> Evidence:
    indices = [negotiation.request_frame]
    if negotiation.response_frame is not None:
        indices.append(negotiation.response_frame)
    return Evidence(method="ike_sa_init_transform", packet_indices=indices)


def _family_inference_note(field: str) -> str:
    return (
        f"the Child SA's {field} is negotiated inside an encrypted exchange "
        "(IKEv1 Quick Mode or IKEv2 IKE_AUTH/CREATE_CHILD_SA) and cannot be "
        "read directly; assumed to match the IKE SA's own negotiated value, "
        "which is the common case but not guaranteed (LLD section 6.4)"
    )


_NO_NEGOTIATION_NOTE: Final = (
    "no IKE negotiation in this capture correlates to this SA by endpoint "
    "and timing (LLD section 6.2); nothing to observe or infer from"
)


_T = TypeVar("_T")


def _ike_family_attribute(
    value: _T | None, negotiation: IkeNegotiation | None, field: str
) -> Attribute[_T]:
    if negotiation is None:
        return Attribute.unavailable(_NO_NEGOTIATION_NOTE)
    if value is None or value is EncryptionAlg.UNKNOWN:
        return Attribute.unavailable(
            f"the IKE SA's own {field} could not be identified from this capture"
        )
    return Attribute.inferred(
        value,
        _SAME_FAMILY_CONFIDENCE,
        evidence=_ike_evidence(negotiation),
        note=_family_inference_note(field),
    )


def assemble_security_association(
    pair: SAPair, negotiation: IkeNegotiation | None
) -> SecurityAssociation:
    """Build one ``SecurityAssociation`` from an ingest ``SAPair`` and the IKE
    negotiation (if any) that step 4.6 correlated to it.

    Every field is either a fact about the ESP/AH packets themselves (the
    identity fields at the top, straight from ``ingest``, no provenance
    needed) or an ``Attribute`` whose provenance reflects exactly what LLD
    section 6.4 says is and is not observable: the IKE SA's own negotiated
    parameters are ``OBSERVED``; the Child SA's crypto, which is never
    visible in cleartext for either IKE version, is an ``INFERRED``
    same-family guess; and operating mode, PFS, rekey timing and replay
    sanity are Track B's job (steps 9.x, not yet built) and are honestly
    ``UNAVAILABLE`` here rather than fabricated.
    """
    forward = pair.forward
    reverse = pair.reverse
    packets = forward.packets + (reverse.packets if reverse else ())
    ip_version = packets[0].ip_version

    ike_version_attr: Attribute[IkeVersion]
    exchange_mode_attr: Attribute[IkeExchangeMode]
    if negotiation is None:
        ike_version_attr = Attribute.unavailable(_NO_NEGOTIATION_NOTE)
        exchange_mode_attr = Attribute.unavailable(_NO_NEGOTIATION_NOTE)
    else:
        ike_version_attr = Attribute.observed(
            negotiation.ike_version, evidence=_ike_evidence(negotiation)
        )
        if negotiation.ike_version is IkeVersion.IKEV2:
            exchange_mode_attr = Attribute.unavailable(
                "IKEv2 has no Phase 1 exchange mode (LLD section 6.4)"
            )
        elif negotiation.exchange_mode is not None:
            exchange_mode_attr = Attribute.observed(
                negotiation.exchange_mode, evidence=_ike_evidence(negotiation)
            )
        else:
            exchange_mode_attr = Attribute.unavailable(
                "the IKEv1 exchange type in this capture was not main or aggressive"
            )

    prf_attr: Attribute[PrfAlg]
    auth_attr: Attribute[AuthMethod]
    if negotiation is None:
        dh_group_attr: Attribute[int] = Attribute.unavailable(_NO_NEGOTIATION_NOTE)
        prf_attr = Attribute.unavailable(_NO_NEGOTIATION_NOTE)
        lifetime_attr: Attribute[int] = Attribute.unavailable(_NO_NEGOTIATION_NOTE)
        auth_attr = Attribute.unavailable(_NO_NEGOTIATION_NOTE)
        esn_attr: Attribute[bool] = Attribute.unavailable(_NO_NEGOTIATION_NOTE)
        nat_attr: Attribute[bool] = Attribute.unavailable(_NO_NEGOTIATION_NOTE)
    else:
        dh_group_attr = (
            Attribute.observed(negotiation.dh_group, evidence=_ike_evidence(negotiation))
            if negotiation.dh_group is not None
            else Attribute.unavailable(
                "no Diffie-Hellman transform was found in the IKE SA proposal"
            )
        )
        if negotiation.ike_version is IkeVersion.IKEV1:
            prf_attr = Attribute.unavailable(
                "IKEv1 derives its PRF from the Phase 1 hash rather than negotiating "
                "it separately (LLD section 6.2)"
            )
        elif negotiation.prf_alg is not None:
            prf_attr = Attribute.observed(negotiation.prf_alg, evidence=_ike_evidence(negotiation))
        else:
            prf_attr = Attribute.unavailable("no PRF transform was found in the IKE SA proposal")

        if negotiation.ike_version is IkeVersion.IKEV2:
            lifetime_attr = Attribute.unavailable(
                "RFC 7296 removed SA lifetime negotiation from IKEv2; each peer expires "
                "on local policy, so no negotiated value exists (LLD section 6.4)"
            )
            auth_attr = Attribute.unavailable(
                "the IKEv2 AUTH payload sits inside the encrypted IKE_AUTH "
                "exchange (LLD section 6.2)"
            )
        else:
            lifetime_attr = (
                Attribute.observed(negotiation.lifetime_s, evidence=_ike_evidence(negotiation))
                if negotiation.lifetime_s is not None
                else Attribute.unavailable(
                    "no seconds-based lifetime attribute was found in the IKE SA proposal"
                )
            )
            auth_attr = (
                Attribute.observed(negotiation.auth_method, evidence=_ike_evidence(negotiation))
                if negotiation.auth_method is not None
                else Attribute.unavailable(
                    "no authentication method attribute was found in the IKE SA proposal"
                )
            )

        esn_attr = (
            Attribute.observed(negotiation.esn, evidence=_ike_evidence(negotiation))
            if negotiation.esn is not None
            else Attribute.unavailable(
                "ESN is negotiated in the Child SA proposal, inside an encrypted exchange, "
                "and is not observable from this capture (LLD section 7.5)"
            )
        )
        nat_attr = Attribute.observed(negotiation.nat_detected, evidence=_ike_evidence(negotiation))

    encryption_alg = negotiation.encryption_alg if negotiation else None
    encryption_keylen = negotiation.encryption_keylen if negotiation else None
    integrity_alg = negotiation.integrity_alg if negotiation else None

    return SecurityAssociation(
        spi_initiator=_spi_hex(forward.key.spi),
        spi_responder=_spi_hex(reverse.key.spi) if reverse else None,
        src=forward.key.src,
        dst=forward.key.dst,
        ip_version=ip_version,
        protocol=forward.key.proto,
        first_seen=_to_utc(min(p.ts for p in packets)),
        last_seen=_to_utc(max(p.ts for p in packets)),
        packet_count=len(packets),
        byte_count=sum(p.ip_payload_len for p in packets),
        ike_version=ike_version_attr,
        ike_exchange_mode=exchange_mode_attr,
        encryption_alg=_ike_family_attribute(encryption_alg, negotiation, "encryption algorithm"),
        encryption_keylen=_ike_family_attribute(encryption_keylen, negotiation, "key length"),
        integrity_alg=_ike_family_attribute(integrity_alg, negotiation, "integrity algorithm"),
        prf_alg=prf_attr,
        dh_group=dh_group_attr,
        operating_mode=Attribute.unavailable(
            "not carried in any cleartext IKE field; inferred from encapsulation "
            "overhead (PRD section 7, LLD section 7.3), which Track B does not "
            "yet implement"
        ),
        pfs_enabled=Attribute.unavailable(
            "PFS is inferred from CREATE_CHILD_SA message sizes (LLD section 7.4), "
            "which Track B does not yet implement"
        ),
        auth_method=auth_attr,
        negotiated_lifetime_s=lifetime_attr,
        observed_rekey_s=Attribute.unavailable(
            "observed rekey interval requires SPI-rotation timing analysis "
            "(LLD section 7.5), which Track B does not yet implement"
        ),
        esn_negotiated=esn_attr,
        replay_sane=Attribute.unavailable(
            "sequence-number analysis (LLD section 7.5) is Track B's job and is not yet implemented"
        ),
        nat_traversal=nat_attr,
        downgrade_available=(
            Attribute.observed(negotiation.downgrade_available, evidence=_ike_evidence(negotiation))
            if negotiation is not None and negotiation.selected is not None
            else Attribute.unavailable(
                "the responder's selected proposal was not captured, so the offered "
                "proposals cannot be compared against it (LLD section 6.3)"
                if negotiation is not None
                else _NO_NEGOTIATION_NOTE
            )
        ),
        inner_traffic=[],
    )


# ===========================================================================
# Pipeline entry point
# ===========================================================================


def run_track_a(
    pcap_path: Path, sa_pairs: list[SAPair], *, tshark_bin: str = "tshark"
) -> list[SecurityAssociation]:
    """Steps 4.1-4.8, end to end: a capture and its assembled SA pairs in,
    one ``SecurityAssociation`` per pair out."""
    raw_packets = run_tshark(pcap_path, tshark_bin=tshark_bin)
    messages = parse_isakmp_json(raw_packets)
    negotiations = build_negotiations(messages)
    return [
        assemble_security_association(pair, correlate_negotiation(pair.forward, negotiations))
        for pair in sa_pairs
    ]

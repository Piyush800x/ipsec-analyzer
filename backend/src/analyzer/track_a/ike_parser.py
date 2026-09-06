"""tshark-backed ISAKMP extraction (LLD 6). Steps 4.1-4.5, 4.7.

LLD section 6.1 is explicit about the approach: shell out to tshark and parse
its JSON rather than hand-rolling ISAKMP dissection, because Wireshark's
dissector already handles every transform-attribute encoding variant. The
same section is equally explicit about the risk: "field names in Wireshark's
JSON output change across releases and will silently break the parser."

That risk is concentrated in exactly one place here --
``_extract_message_fields`` and its helpers, which read tshark's raw
``_source.layers`` JSON. Every field lookup below goes through
``_find_int``/``_find_str`` or a named constant so that a future field-name
correction touches this function and nothing downstream of it. Everything
past that boundary (``Proposal``, ``Transform``, ``IkeNegotiation`` and the
building of one from the other) works on the plain IR in this module and is
independent of tshark's JSON shape.

**This adapter has not been run against a real tshark binary.** No Docker and
no tshark were available where Phase 4 was implemented (see CHANGELOG.md).
Its field-name assumptions are the best available from documented, long-
stable ``isakmp.*`` display-filter names, deliberately read defensively
(multiple candidate keys, tolerant integer parsing) rather than assumed
exact -- but LLD section 6.1's warning applies at full strength until someone
runs this against a real capture and fixes what tshark actually calls things.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from analyzer.core.enums import (
    AuthMethod,
    EncryptionAlg,
    IkeExchangeMode,
    IkeVersion,
    IntegrityAlg,
    PrfAlg,
)
from analyzer.track_a.transforms import (
    ATTR_KEY_LENGTH,
    IKEV1_ATTR_AUTH_METHOD,
    IKEV1_ATTR_ENCRYPTION_ALGORITHM,
    IKEV1_ATTR_GROUP_DESCRIPTION,
    IKEV1_ATTR_HASH_ALGORITHM,
    IKEV1_ATTR_LIFE_DURATION,
    IKEV1_ATTR_LIFE_TYPE,
    IKEV1_LIFE_TYPE_SECONDS,
    TRANSFORM_TYPE_DH,
    TRANSFORM_TYPE_ENCR,
    TRANSFORM_TYPE_ESN,
    TRANSFORM_TYPE_INTEG,
    TRANSFORM_TYPE_PRF,
    ikev1_auth_method,
    ikev1_encryption_alg,
    ikev1_hash_alg,
    ikev2_encryption_alg,
    ikev2_integrity_alg,
    ikev2_prf_alg,
    is_weaker_encryption,
)

DEFAULT_TIMEOUT_S: Final = 60.0

IKE_EXCHANGE_TYPE_MAIN: Final = 2
IKE_EXCHANGE_TYPE_AGGRESSIVE: Final = 4
"""IKEv1 Phase 1 exchange types, RFC 2408 section 3.1. Step 4.3."""

NOTIFY_NAT_DETECTION_SOURCE_IP: Final = 16406
NOTIFY_NAT_DETECTION_DESTINATION_IP: Final = 16407
"""RFC 3947 NAT-Traversal notify message types. Step 4.7."""


class TrackAError(RuntimeError):
    """tshark could not be run, or its output could not be parsed."""


# ===========================================================================
# Intermediate representation. LLD section 6.3 gives ``Proposal``'s role
# (proposed vs selected); its field shape, and ``Transform``/``TransformAttr``
# below it, are this module's design -- LLD names the type without a schema.
# ===========================================================================


@dataclass(frozen=True, slots=True)
class TransformAttr:
    attr_type: int
    value: int


@dataclass(frozen=True, slots=True)
class Transform:
    transform_type: int
    transform_id: int
    attrs: tuple[TransformAttr, ...] = ()

    def attr(self, attr_type: int) -> int | None:
        return next((a.value for a in self.attrs if a.attr_type == attr_type), None)


@dataclass(frozen=True, slots=True)
class Proposal:
    """LLD section 6.3: one numbered proposal offering candidate transforms."""

    number: int
    protocol_id: int
    transforms: tuple[Transform, ...]

    def transform(self, transform_type: int) -> Transform | None:
        return next((t for t in self.transforms if t.transform_type == transform_type), None)


@dataclass(frozen=True, slots=True)
class IsakmpMessage:
    """One ISAKMP packet's outer-header facts, plus its SA payload when this
    is a message Wireshark can dissect without decryption keys.

    Only Phase 1 (IKEv1) and ``IKE_SA_INIT`` (IKEv2) carry a cleartext SA
    payload; ``sa_payload`` is ``None`` for everything after (IKEv1 Quick
    Mode, IKEv2 ``IKE_AUTH`` and later), which this reader never attempts to
    dissect because there is nothing in it tshark can show without keys.
    """

    frame_index: int
    ts: float
    src: str
    dst: str
    ike_version: IkeVersion
    exchange_type: int
    message_id: int
    init_spi: str
    resp_spi: str
    sa_payload: tuple[Proposal, ...] | None
    nat_detected: bool


@dataclass(frozen=True, slots=True)
class IkeNegotiation:
    """One IKE SA negotiation, proposed vs selected. LLD section 6.3.

    Every field here describes the IKE SA itself -- the thing that protects
    the negotiation -- because that is genuinely what a Phase 1 /
    ``IKE_SA_INIT`` SA payload proposes. It is *not* the Child SA's crypto:
    that is negotiated inside an encrypted exchange (IKEv1 Quick Mode, IKEv2
    ``IKE_AUTH``/``CREATE_CHILD_SA``) this reader never attempts to read.
    ``track_a/correlate.py`` is where an IKE SA's parameters become an
    ``INFERRED`` same-family guess about a ``SecurityAssociation``'s Child
    SA, per LLD section 6.4 -- not here, and not as ``OBSERVED``.
    """

    ike_version: IkeVersion
    exchange_mode: IkeExchangeMode | None
    init_spi: str
    resp_spi: str | None
    src: str
    dst: str
    ts: float
    request_frame: int
    response_frame: int | None

    proposed: tuple[Proposal, ...]
    selected: Proposal | None
    downgrade_available: bool

    dh_group: int | None
    prf_alg: PrfAlg | None
    encryption_alg: EncryptionAlg | None
    encryption_keylen: int | None
    integrity_alg: IntegrityAlg | None
    lifetime_s: int | None
    auth_method: AuthMethod | None
    esn: bool | None
    nat_detected: bool


# ===========================================================================
# Step 4.1: the tshark subprocess
# ===========================================================================


def run_tshark(
    pcap_path: Path, *, tshark_bin: str = "tshark", timeout_s: float = DEFAULT_TIMEOUT_S
) -> list[dict[str, Any]]:
    """Run tshark's ISAKMP dissector over *pcap_path* and return its parsed JSON.

    ``--no-duplicate-keys`` is load-bearing: without it, tshark's default JSON
    rendering collapses a repeated field name (multiple proposals, multiple
    transforms) into one overwritten value instead of a list.
    """
    if shutil.which(tshark_bin) is None:
        msg = f"{tshark_bin!r} is not on PATH; Track A cannot run without it (LLD section 6.1)"
        raise TrackAError(msg)

    cmd = [tshark_bin, "-r", str(pcap_path), "-Y", "isakmp", "-T", "json", "--no-duplicate-keys"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
    except subprocess.TimeoutExpired as exc:
        msg = f"tshark timed out after {timeout_s}s reading {pcap_path}"
        raise TrackAError(msg) from exc

    if result.returncode != 0:
        msg = f"tshark exited {result.returncode} reading {pcap_path}: {result.stderr.strip()}"
        raise TrackAError(msg)

    if not result.stdout.strip():
        return []

    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        msg = f"tshark produced output that is not valid JSON for {pcap_path}: {exc}"
        raise TrackAError(msg) from exc

    if not isinstance(parsed, list):
        msg = f"expected a JSON array of packets from tshark, got {type(parsed).__name__}"
        raise TrackAError(msg)
    return parsed


# ===========================================================================
# Steps 4.2, 4.3: tshark JSON -> IsakmpMessage. The one adapter boundary.
# ===========================================================================


def _as_list(value: Any) -> list[Any]:
    """tshark JSON collapses a singleton repeated element to a bare object
    rather than a one-element list on some versions even with
    ``--no-duplicate-keys``. Every repeated ISAKMP structure (proposals,
    transforms, attributes) is read through this so both shapes work."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _to_int(value: Any) -> int | None:
    """Tolerant integer parsing for a tshark field value.

    Numeric ISAKMP fields render as plain decimal strings in most tshark
    versions, but a value-string lookup on the same field can instead render
    ``"AES-CBC (12)"`` or a hex string. All three are tried before giving up,
    because guessing wrong here must fail loudly (return ``None``, which
    becomes ``UNKNOWN``/``UNAVAILABLE`` downstream) rather than silently.
    """
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 0) if text.lower().startswith("0x") else int(text)
        except ValueError:
            pass
        if "(" in text and text.endswith(")"):
            inner = text.rsplit("(", 1)[1][:-1].strip()
            try:
                return int(inner, 0) if inner.lower().startswith("0x") else int(inner)
            except ValueError:
                return None
    return None


def _layers(packet: dict[str, Any]) -> dict[str, Any]:
    source = packet.get("_source", {})
    layers = source.get("layers", {})
    return layers if isinstance(layers, dict) else {}


def _find_first(d: dict[str, Any], *candidate_keys: str) -> Any:
    for key in candidate_keys:
        if key in d:
            return d[key]
    return None


def _find_by_suffix(d: dict[str, Any], suffix: str) -> Any:
    """Find a value by key suffix rather than an assumed exact dotted path.

    Used only inside one transform-attribute object, where the search space
    is small enough that a suffix match is precise. This is the module's
    hedge against getting the deepest, least-documented part of the ISAKMP
    JSON tree's exact key names wrong.
    """
    for key, value in d.items():
        if key.endswith(suffix):
            return value
    return None


def _outer_endpoints(layers: dict[str, Any]) -> tuple[str, str]:
    ip = layers.get("ip")
    if isinstance(ip, dict):
        return str(ip.get("ip.src", "")), str(ip.get("ip.dst", ""))
    ipv6 = layers.get("ipv6")
    if isinstance(ipv6, dict):
        return str(ipv6.get("ipv6.src", "")), str(ipv6.get("ipv6.dst", ""))
    return "", ""


def _frame_index_and_ts(layers: dict[str, Any]) -> tuple[int, float]:
    frame = layers.get("frame", {})
    index = _to_int(frame.get("frame.number")) if isinstance(frame, dict) else None
    ts_raw = frame.get("frame.time_epoch") if isinstance(frame, dict) else None
    try:
        ts = float(ts_raw) if ts_raw is not None else 0.0
    except (TypeError, ValueError):
        ts = 0.0
    return index or 0, ts


def _ike_version(isakmp: dict[str, Any]) -> IkeVersion:
    raw = _find_first(isakmp, "isakmp.version", "isakmp.majorversion")
    if isinstance(raw, str) and "." in raw:
        major = raw.split(".", 1)[0].strip()
    else:
        major = str(_to_int(raw) or 0)
    return IkeVersion.IKEV2 if major.strip() in ("2",) else IkeVersion.IKEV1


def _parse_attrs(attr_container: Any) -> tuple[TransformAttr, ...]:
    attrs = []
    for raw_attr in _as_list(attr_container):
        if not isinstance(raw_attr, dict):
            continue
        attr_type = _to_int(_find_by_suffix(raw_attr, ".type"))
        attr_value = _to_int(_find_by_suffix(raw_attr, ".value"))
        if attr_type is not None and attr_value is not None:
            attrs.append(TransformAttr(attr_type=attr_type, value=attr_value))
    return tuple(attrs)


def _parse_transforms(transform_container: Any) -> tuple[Transform, ...]:
    transforms = []
    for raw_tf in _as_list(transform_container):
        if not isinstance(raw_tf, dict):
            continue
        t_type = _to_int(_find_first(raw_tf, "isakmp.tf.type"))
        t_id = _to_int(_find_first(raw_tf, "isakmp.tf.id"))
        if t_type is None or t_id is None:
            continue
        attr_container = _find_first(raw_tf, "isakmp.tf.attr", "isakmp.tf.attrs")
        transforms.append(
            Transform(transform_type=t_type, transform_id=t_id, attrs=_parse_attrs(attr_container))
        )
    return tuple(transforms)


def _parse_proposals(sa_payload: Any) -> tuple[Proposal, ...] | None:
    if not isinstance(sa_payload, dict):
        return None
    proposals_container = _find_first(sa_payload, "isakmp.sa.proposals")
    proposal_container = (
        _find_first(proposals_container, "isakmp.sa.proposal")
        if isinstance(proposals_container, dict)
        else proposals_container
    )
    proposals = []
    for raw_prop in _as_list(proposal_container):
        if not isinstance(raw_prop, dict):
            continue
        number = _to_int(_find_first(raw_prop, "isakmp.prop.number")) or 0
        protocol_id = _to_int(_find_first(raw_prop, "isakmp.prop.protoid")) or 0
        tf_container = _find_first(raw_prop, "isakmp.tf")
        proposals.append(
            Proposal(
                number=number, protocol_id=protocol_id, transforms=_parse_transforms(tf_container)
            )
        )
    return tuple(proposals) if proposals else None


def _nat_detected(isakmp: dict[str, Any]) -> bool:
    notify_container = _find_first(isakmp, "isakmp.notify")
    for raw_notify in _as_list(notify_container):
        if not isinstance(raw_notify, dict):
            continue
        msg_type = _to_int(_find_first(raw_notify, "isakmp.notify.msgtype"))
        if msg_type in (NOTIFY_NAT_DETECTION_SOURCE_IP, NOTIFY_NAT_DETECTION_DESTINATION_IP):
            return True
    return False


def parse_isakmp_json(raw_packets: Sequence[dict[str, Any]]) -> list[IsakmpMessage]:
    """The one function that reads tshark's raw JSON shape. Steps 4.2, 4.3."""
    messages = []
    for packet in raw_packets:
        layers = _layers(packet)
        isakmp = layers.get("isakmp")
        if not isinstance(isakmp, dict):
            continue

        frame_index, ts = _frame_index_and_ts(layers)
        src, dst = _outer_endpoints(layers)
        ike_version = _ike_version(isakmp)
        exchange_type = _to_int(_find_first(isakmp, "isakmp.exchangetype")) or 0
        message_id = _to_int(_find_first(isakmp, "isakmp.messageid")) or 0
        init_spi = str(_find_first(isakmp, "isakmp.init_spi", "isakmp.icookie") or "")
        resp_spi = str(_find_first(isakmp, "isakmp.resp_spi", "isakmp.rcookie") or "")
        sa_payload = _parse_proposals(_find_first(isakmp, "isakmp.sa"))

        messages.append(
            IsakmpMessage(
                frame_index=frame_index,
                ts=ts,
                src=src,
                dst=dst,
                ike_version=ike_version,
                exchange_type=exchange_type,
                message_id=message_id,
                init_spi=init_spi,
                resp_spi=resp_spi,
                sa_payload=sa_payload,
                nat_detected=_nat_detected(isakmp),
            )
        )
    return messages


# ===========================================================================
# Step 4.4: proposed vs selected. Steps 4.3, 4.5, 4.7 fold in here too --
# exchange mode, lifetime, and auth method are all read from the same SA
# payload structure once tshark has decoded it.
# ===========================================================================


def build_negotiations(messages: Sequence[IsakmpMessage]) -> list[IkeNegotiation]:
    """Group messages by ``init_spi`` and turn each group into one negotiation.

    Only messages carrying a cleartext SA payload take part -- IKEv1 Quick
    Mode and IKEv2 ``IKE_AUTH``/later messages share an ``init_spi`` with
    their Phase 1 / ``IKE_SA_INIT`` messages but carry ``sa_payload=None``,
    so they are excluded here rather than needing a separate exchange-type
    filter.

    The earlier message (by capture order) in a group is the request/
    proposed side and the later one the response/selected side. IKEv2 has an
    explicit "R" flag for this that this reader does not use; IKEv1 has none
    at all. Capture order is reliable for both and needs no per-version
    special-casing.
    """
    groups: dict[str, list[IsakmpMessage]] = {}
    order: list[str] = []
    for message in messages:
        if message.sa_payload is None:
            continue
        if message.init_spi not in groups:
            groups[message.init_spi] = []
            order.append(message.init_spi)
        groups[message.init_spi].append(message)

    negotiations = []
    for init_spi in order:
        group = sorted(groups[init_spi], key=lambda m: (m.ts, m.frame_index))
        request = group[0]
        response = group[1] if len(group) > 1 else None
        negotiations.append(_build_negotiation(request, response))
    return negotiations


def _build_negotiation(request: IsakmpMessage, response: IsakmpMessage | None) -> IkeNegotiation:
    ike_version = request.ike_version
    proposed = request.sa_payload or ()
    selected = response.sa_payload[0] if response and response.sa_payload else None

    return IkeNegotiation(
        ike_version=ike_version,
        exchange_mode=_exchange_mode(ike_version, request.exchange_type),
        init_spi=request.init_spi,
        resp_spi=response.resp_spi if response else None,
        src=request.src,
        dst=request.dst,
        ts=response.ts if response else request.ts,
        request_frame=request.frame_index,
        response_frame=response.frame_index if response else None,
        proposed=proposed,
        selected=selected,
        downgrade_available=_downgrade_available(proposed, selected, ike_version),
        dh_group=_dh_group(selected, ike_version),
        prf_alg=_prf_alg(selected, ike_version),
        encryption_alg=_encryption(selected, ike_version)[0],
        encryption_keylen=_encryption(selected, ike_version)[1],
        integrity_alg=_integrity(selected, ike_version),
        lifetime_s=_lifetime_s(selected, ike_version),
        auth_method=_auth_method(selected, ike_version),
        esn=_esn(selected),
        nat_detected=request.nat_detected or (response.nat_detected if response else False),
    )


def _exchange_mode(ike_version: IkeVersion, exchange_type: int) -> IkeExchangeMode | None:
    """Step 4.3. ``None`` for IKEv2, which has no Phase 1 exchange-mode concept."""
    if ike_version is IkeVersion.IKEV2:
        return None
    if exchange_type == IKE_EXCHANGE_TYPE_MAIN:
        return IkeExchangeMode.MAIN
    if exchange_type == IKE_EXCHANGE_TYPE_AGGRESSIVE:
        return IkeExchangeMode.AGGRESSIVE
    return None


def _encryption(
    selected: Proposal | None, ike_version: IkeVersion
) -> tuple[EncryptionAlg | None, int | None]:
    if selected is None:
        return None, None
    if ike_version is IkeVersion.IKEV2:
        t = selected.transform(TRANSFORM_TYPE_ENCR)
        return (
            (ikev2_encryption_alg(t.transform_id), t.attr(ATTR_KEY_LENGTH)) if t else (None, None)
        )
    t = selected.transforms[0] if selected.transforms else None
    if t is None:
        return None, None
    raw = t.attr(IKEV1_ATTR_ENCRYPTION_ALGORITHM)
    return (ikev1_encryption_alg(raw), t.attr(ATTR_KEY_LENGTH)) if raw is not None else (None, None)


def _integrity(selected: Proposal | None, ike_version: IkeVersion) -> IntegrityAlg | None:
    if selected is None:
        return None
    if ike_version is IkeVersion.IKEV2:
        t = selected.transform(TRANSFORM_TYPE_INTEG)
        return ikev2_integrity_alg(t.transform_id) if t else None
    t = selected.transforms[0] if selected.transforms else None
    raw = t.attr(IKEV1_ATTR_HASH_ALGORITHM) if t else None
    return ikev1_hash_alg(raw) if raw is not None else None


def _prf_alg(selected: Proposal | None, ike_version: IkeVersion) -> PrfAlg | None:
    """IKEv2 only -- IKEv1 derives its PRF from the Phase 1 hash. LLD section 6.2."""
    if ike_version is not IkeVersion.IKEV2 or selected is None:
        return None
    t = selected.transform(TRANSFORM_TYPE_PRF)
    return ikev2_prf_alg(t.transform_id) if t else None


def _dh_group(selected: Proposal | None, ike_version: IkeVersion) -> int | None:
    if selected is None:
        return None
    if ike_version is IkeVersion.IKEV2:
        t = selected.transform(TRANSFORM_TYPE_DH)
        return t.transform_id if t else None
    t = selected.transforms[0] if selected.transforms else None
    return t.attr(IKEV1_ATTR_GROUP_DESCRIPTION) if t else None


def _lifetime_s(selected: Proposal | None, ike_version: IkeVersion) -> int | None:
    """Step 4.5. IKEv1 attributes 11/12 only -- RFC 7296 removed lifetime
    negotiation from IKEv2 entirely, so this is always ``None`` there."""
    if ike_version is not IkeVersion.IKEV1 or selected is None or not selected.transforms:
        return None
    t = selected.transforms[0]
    life_type = t.attr(IKEV1_ATTR_LIFE_TYPE)
    duration = t.attr(IKEV1_ATTR_LIFE_DURATION)
    return duration if life_type == IKEV1_LIFE_TYPE_SECONDS and duration is not None else None


def _auth_method(selected: Proposal | None, ike_version: IkeVersion) -> AuthMethod | None:
    """Step 4.7. IKEv1 transform attribute 3 only -- the IKEv2 AUTH payload
    sits inside encrypted ``IKE_AUTH``, so this is always ``None`` there."""
    if ike_version is not IkeVersion.IKEV1 or selected is None or not selected.transforms:
        return None
    raw = selected.transforms[0].attr(IKEV1_ATTR_AUTH_METHOD)
    return ikev1_auth_method(raw) if raw is not None else None


def _esn(selected: Proposal | None) -> bool | None:
    if selected is None:
        return None
    t = selected.transform(TRANSFORM_TYPE_ESN)
    return t.transform_id == 1 if t else None


def _all_encryption_choices(
    proposal: Proposal, ike_version: IkeVersion
) -> list[tuple[EncryptionAlg, int | None]]:
    choices: list[tuple[EncryptionAlg, int | None]] = []
    if ike_version is IkeVersion.IKEV2:
        for t in proposal.transforms:
            if t.transform_type == TRANSFORM_TYPE_ENCR:
                choices.append((ikev2_encryption_alg(t.transform_id), t.attr(ATTR_KEY_LENGTH)))
        return choices
    for t in proposal.transforms:
        raw = t.attr(IKEV1_ATTR_ENCRYPTION_ALGORITHM)
        if raw is not None:
            choices.append((ikev1_encryption_alg(raw), t.attr(ATTR_KEY_LENGTH)))
    return choices


def _downgrade_available(
    proposed: tuple[Proposal, ...], selected: Proposal | None, ike_version: IkeVersion
) -> bool:
    """Step 4.4: was a weaker encryption choice offered than what was selected?

    LLD section 6.3: offering 3DES alongside AES-256 is a real weakness even
    when AES-256 was chosen, because an active attacker who can influence the
    negotiation may force the weaker option.
    """
    if selected is None:
        return False
    selected_alg, selected_keylen = _encryption(selected, ike_version)
    if selected_alg is None:
        return False
    selected_choice = (selected_alg, selected_keylen)
    return any(
        is_weaker_encryption(candidate, selected_choice)
        for proposal in proposed
        for candidate in _all_encryption_choices(proposal, ike_version)
    )

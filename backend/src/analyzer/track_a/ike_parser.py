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

**This adapter has now been run against the pinned tshark (4.4.18) on real
strongSwan captures, and most of what it assumed was wrong.** Phase 4 was
written without Docker or tshark and guessed the field names from documented
``isakmp.*`` display-filter names; every one of the structural guesses missed.
tshark does not expose ``isakmp.sa.proposals``/``isakmp.tf`` container keys at
all -- it nests payloads as repeated ``isakmp.typepayload`` /
``isakmp.typepayload_tree`` pairs -- IKEv1 attributes live under
``isakmp.ike.attr`` rather than ``isakmp.tf.attr``, IKEv2 spells the transform
ID once per transform type (``isakmp.tf.id.encr`` and friends), and
``isakmp.version`` is the packed byte ``0x20`` rather than a major version.
The result was a parser that ran cleanly and observed *nothing*: every
capture came back "no IKE negotiation correlates to this SA".

The names below are now read off real output rather than inferred, and
``tests/test_track_a_ike_parser.py`` fixtures are captured from that same
output. LLD section 6.1's warning still applies to the *next* tshark version:
this is an adapter to one program's JSON, and it is pinned for that reason.
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
    fixed_key_length_bits,
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

IKE_EXCHANGE_TYPE_CREATE_CHILD_SA: Final = 36
IKE_EXCHANGE_TYPE_INFORMATIONAL: Final = 37
"""RFC 7296 section 1.2-1.4 exchange types. Step 9.4 measures the size delta
between the two: a CREATE_CHILD_SA carrying a KE payload is larger than one
that does not by the DH group's public-value size, and an INFORMATIONAL
exchange over the same SA is the nearest thing to a KE-free baseline that a
capture offers."""

NOTIFY_NAT_DETECTION_SOURCE_IP: Final = 16388
NOTIFY_NAT_DETECTION_DESTINATION_IP: Final = 16389
"""RFC 7296 section 3.10.1 NAT detection notify types, confirmed as 16388 on a
real IKE_SA_INIT. Step 4.7. Phase 4 had 16406/16407 here, which are not the
NAT-detection types in either RFC and matched nothing."""

PAYLOAD_TYPE_KEY: Final = "isakmp.typepayload"
PAYLOAD_TREE_KEY: Final = "isakmp.typepayload_tree"
"""How tshark renders the ISAKMP payload chain, and the single most important
fact about its JSON: a payload is *two* sibling keys, not one object. The type
number lands in ``isakmp.typepayload`` and the payload's contents in
``isakmp.typepayload_tree``, both repeated once per payload and aligned by
position. Nesting uses the same pair recursively, so a transform is reached as
SA -> proposal -> transform through three levels of it.

``--no-duplicate-keys`` turns the repetitions into JSON arrays. Without it they
collapse to whichever payload tshark emitted last, which for an IKE_SA_INIT is
a vendor ID rather than the SA payload."""

PAYLOAD_IKEV1_SA: Final = 1
PAYLOAD_PROPOSAL: Final = 2
PAYLOAD_TRANSFORM: Final = 3
PAYLOAD_IKEV1_NAT_D: Final = 20
PAYLOAD_IKEV1_NOTIFY: Final = 11
PAYLOAD_IKEV2_SA: Final = 33
PAYLOAD_IKEV2_NOTIFY: Final = 41
"""ISAKMP payload type numbers (RFC 2408 section 3.1, RFC 7296 section 3.2).
Proposal and Transform keep the same numbers in both versions; SA and Notify
do not."""

SA_PAYLOAD_TYPES: Final = frozenset({PAYLOAD_IKEV1_SA, PAYLOAD_IKEV2_SA})
NOTIFY_PAYLOAD_TYPES: Final = frozenset({PAYLOAD_IKEV1_NOTIFY, PAYLOAD_IKEV2_NOTIFY})

IKEV1_ATTR_CONTAINER: Final = "isakmp.ike.attr"
IKEV2_ATTR_CONTAINER: Final = "isakmp.ike2.attr"
"""Transform attributes. The two IKE versions get different key names from
tshark even where the encoding is identical, so neither can stand in for the
other. Phase 4 assumed a single ``isakmp.tf.attr`` for both; that key does not
exist."""

IKEV1_NO_TRANSFORM_TYPE: Final = -1
"""IKEv1 transforms have no transform *type*: one transform payload carries a
whole candidate suite and every algorithm in it is an attribute. A sentinel
rather than a borrowed number, so that ``Proposal.transform()`` -- which asks
an IKEv2-shaped question -- can never match an IKEv1 transform and read it
under the wrong version's rules."""


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
    length: int = 0
    """The ISAKMP message length in bytes, from the header's own length field.

    Read from ``isakmp.length`` rather than the frame length so that it measures
    the IKE message and not the Ethernet, IP and UDP headers around it -- those
    are constant per capture but not across captures, and step 9.4 compares
    sizes between exchanges rather than against an absolute."""


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
        if ":" in text:
            # Transform attribute values arrive as colon-separated octets:
            # "00:05" for an algorithm ID, "00:01:73:40" for a lifetime. This
            # is the raw attribute value in network byte order, so a plain
            # big-endian read is the decode, not a heuristic.
            try:
                return int.from_bytes(bytes.fromhex(text.replace(":", "")), "big")
            except ValueError:
                return None
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


def _child_payloads(node: dict[str, Any]) -> list[tuple[int, dict[str, Any]]]:
    """The ISAKMP payloads directly inside *node*, as ``(type, contents)``.

    The two repeated keys are aligned by position, which is the only thing
    tying a payload's type number to its contents -- tshark does not put the
    type inside the tree. ``zip`` therefore truncates deliberately: a run
    where the two lists disagree in length is malformed output, and pairing
    past the shorter one would attach contents to the wrong type.
    """
    types = _as_list(node.get(PAYLOAD_TYPE_KEY))
    trees = _as_list(node.get(PAYLOAD_TREE_KEY))
    payloads = []
    for raw_type, tree in zip(types, trees, strict=False):
        payload_type = _to_int(raw_type)
        if payload_type is not None and isinstance(tree, dict):
            payloads.append((payload_type, tree))
    return payloads


def _payloads_of_type(node: dict[str, Any], wanted: frozenset[int] | int) -> list[dict[str, Any]]:
    """Direct children of *node* whose payload type is in *wanted*."""
    types = wanted if isinstance(wanted, frozenset) else frozenset({wanted})
    return [tree for payload_type, tree in _child_payloads(node) if payload_type in types]


def _walk_payloads(node: dict[str, Any]) -> list[tuple[int, dict[str, Any]]]:
    """Every payload under *node*, at any depth, breadth-first.

    Used where the payload's position in the chain does not matter, only that
    it is somewhere in the message -- NAT detection being the case that
    motivates it, since the notify can sit at any point in the chain.
    """
    found: list[tuple[int, dict[str, Any]]] = []
    queue = [node]
    while queue:
        current = queue.pop(0)
        children = _child_payloads(current)
        found.extend(children)
        queue.extend(tree for _, tree in children)
    return found


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


def _find_by_prefix(d: dict[str, Any], prefix: str) -> Any:
    """Find a value by key prefix, for a field tshark names after its own
    interpretation of the value.

    An IKEv2 transform ID is ``isakmp.tf.id.encr``, ``isakmp.tf.id.prf``,
    ``isakmp.tf.id.integ``, ``isakmp.tf.id.dh`` or ``isakmp.tf.id.esn``
    depending on the transform type that precedes it. Matching the prefix
    reads all five, and the older bare ``isakmp.tf.id``, without enumerating
    a list that a new transform type would silently fall off the end of.
    """
    for key, value in d.items():
        if key.startswith(prefix):
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
    """The IKE major version, from whichever of three renderings tshark used.

    ``isakmp.version`` is the *packed* version byte -- ``0x20`` for IKEv2 and
    ``0x10`` for IKEv1 -- with the nibbles split out into
    ``isakmp.version_tree``. Reading the packed byte as an integer gives 32,
    which is not 2, so Phase 4's version check classified every IKEv2 capture
    as IKEv1 and then looked for IKEv1 attributes that were not there. The
    unpacked nibble is preferred and the shift is the fallback.
    """
    tree = isakmp.get("isakmp.version_tree")
    if isinstance(tree, dict):
        major = _to_int(_find_first(tree, "isakmp.mjver"))
        if major is not None:
            return IkeVersion.IKEV2 if major == 2 else IkeVersion.IKEV1

    spelled = _find_first(isakmp, "isakmp.majorversion")
    if spelled is not None:
        return IkeVersion.IKEV2 if _to_int(spelled) == 2 else IkeVersion.IKEV1

    raw = isakmp.get("isakmp.version")
    if isinstance(raw, str) and "." in raw:
        return IkeVersion.IKEV2 if _to_int(raw.split(".", 1)[0]) == 2 else IkeVersion.IKEV1

    packed = _to_int(raw)
    if packed is not None:
        return IkeVersion.IKEV2 if (packed >> 4) == 2 else IkeVersion.IKEV1
    return IkeVersion.IKEV1


def _spi(value: Any) -> str:
    """An ISAKMP cookie, normalised from tshark's ``e8:e0:79:...`` octets to
    bare lowercase hex, so an IKE SPI reads the same way ingest renders an ESP
    SPI. Also the negotiation grouping key, which only needs consistency."""
    return str(value or "").replace(":", "").lower()


def _parse_attrs(attr_container: Any) -> tuple[TransformAttr, ...]:
    """Transform attributes, from either version's container.

    The suffixes are ``.attr.type`` and ``.attr.value`` rather than ``.type``
    and ``.value`` because tshark also emits *decoded* siblings in the same
    object -- ``isakmp.ike.attr.life_type``, ``isakmp.ike.attr.encryption_algorithm``
    -- and a bare ``.type`` suffix matches whichever the dict happens to yield
    first. The raw ``value`` is read rather than the decoded sibling because it
    is present for every attribute type, including ones tshark has no name for.
    """
    attrs = []
    for raw_attr in _as_list(attr_container):
        if not isinstance(raw_attr, dict):
            continue
        attr_type = _to_int(_find_by_suffix(raw_attr, ".attr.type"))
        attr_value = _to_int(_find_by_suffix(raw_attr, ".attr.value"))
        if attr_type is not None and attr_value is not None:
            attrs.append(TransformAttr(attr_type=attr_type, value=attr_value))
    return tuple(attrs)


def _ikev2_transform(raw_tf: dict[str, Any]) -> Transform | None:
    """One typed IKEv2 transform: ENCR, PRF, INTEG, DH or ESN."""
    t_type = _to_int(_find_first(raw_tf, "isakmp.tf.type"))
    t_id = _to_int(_find_by_prefix(raw_tf, "isakmp.tf.id"))
    if t_type is None or t_id is None:
        return None
    attrs = _parse_attrs(_find_first(raw_tf, IKEV2_ATTR_CONTAINER))
    return Transform(transform_type=t_type, transform_id=t_id, attrs=attrs)


def _ikev1_transform(raw_tf: dict[str, Any]) -> Transform | None:
    """One IKEv1 transform: a whole candidate suite carried as attributes.

    ``isakmp.trans.id`` is the transform ID (``KEY_IKE`` for Phase 1); the
    algorithms are all in ``isakmp.ike.attr``. See ``IKEV1_NO_TRANSFORM_TYPE``
    for why the type is a sentinel.
    """
    t_id = _to_int(_find_first(raw_tf, "isakmp.trans.id"))
    if t_id is None:
        return None
    attrs = _parse_attrs(_find_first(raw_tf, IKEV1_ATTR_CONTAINER))
    return Transform(transform_type=IKEV1_NO_TRANSFORM_TYPE, transform_id=t_id, attrs=attrs)


def _parse_transforms(
    proposal_tree: dict[str, Any], ike_version: IkeVersion
) -> tuple[Transform, ...]:
    parse = _ikev2_transform if ike_version is IkeVersion.IKEV2 else _ikev1_transform
    transforms = [parse(tree) for tree in _payloads_of_type(proposal_tree, PAYLOAD_TRANSFORM)]
    return tuple(t for t in transforms if t is not None)


def _parse_proposals(
    isakmp: dict[str, Any], ike_version: IkeVersion
) -> tuple[Proposal, ...] | None:
    """Every proposal in every SA payload of one message, or ``None``.

    ``None`` rather than an empty tuple is the signal ``build_negotiations``
    uses to skip a message that carries no cleartext SA payload at all --
    IKEv1 Quick Mode, IKEv2 IKE_AUTH -- which is most of a capture.
    """
    proposals = []
    for sa_tree in _payloads_of_type(isakmp, SA_PAYLOAD_TYPES):
        for prop_tree in _payloads_of_type(sa_tree, PAYLOAD_PROPOSAL):
            proposals.append(
                Proposal(
                    number=_to_int(_find_first(prop_tree, "isakmp.prop.number")) or 0,
                    protocol_id=_to_int(_find_first(prop_tree, "isakmp.prop.protoid")) or 0,
                    transforms=_parse_transforms(prop_tree, ike_version),
                )
            )
    return tuple(proposals) if proposals else None


def _nat_detected(isakmp: dict[str, Any]) -> bool:
    """Whether this message carries NAT-detection payloads. Step 4.7.

    This is "the peers ran NAT discovery", not "a NAT was found": the answer
    to the latter is a comparison of the hash in the payload against one
    computed over the observed addresses, and a capture taken on one side
    cannot make it. LLD section 6.4 treats the presence of the exchange as the
    observable, and ``correlate.py`` reports it under that name.

    IKEv2 carries the discovery as notify types 16388/16389. IKEv1 (RFC 3947)
    carries it as its own NAT-D payload type instead, with no notify at all,
    so a notify-only check answers ``False`` for every IKEv1 capture.
    """
    for payload_type, tree in _walk_payloads(isakmp):
        if payload_type == PAYLOAD_IKEV1_NAT_D:
            return True
        if payload_type not in NOTIFY_PAYLOAD_TYPES:
            continue
        msg_type = _to_int(_find_first(tree, "isakmp.notify.msgtype"))
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
        init_spi = _spi(_find_first(isakmp, "isakmp.ispi", "isakmp.init_spi", "isakmp.icookie"))
        resp_spi = _spi(_find_first(isakmp, "isakmp.rspi", "isakmp.resp_spi", "isakmp.rcookie"))
        sa_payload = _parse_proposals(isakmp, ike_version)
        length = _to_int(_find_first(isakmp, "isakmp.length")) or 0

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
                length=length,
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
        if t is None:
            return None, None
        alg = ikev2_encryption_alg(t.transform_id)
        return alg, _keylen(t, alg)
    t = selected.transforms[0] if selected.transforms else None
    if t is None:
        return None, None
    raw = t.attr(IKEV1_ATTR_ENCRYPTION_ALGORITHM)
    if raw is None:
        return None, None
    alg = ikev1_encryption_alg(raw)
    return alg, _keylen(t, alg)


def _keylen(transform: Transform, alg: EncryptionAlg) -> int | None:
    """The negotiated key length, or the one the cipher fixes by definition.

    A 3DES proposal carries no key-length attribute because 3DES has nothing
    to negotiate, and returning ``None`` there reports "unknown" for a value
    that is not unknown at all. The attribute always wins when present, so
    this cannot overwrite something actually observed.
    """
    negotiated = transform.attr(ATTR_KEY_LENGTH)
    return negotiated if negotiated is not None else fixed_key_length_bits(alg)


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


# ===========================================================================
# Step 9.4's input: exchange sizes, grouped by endpoint pair
# ===========================================================================


@dataclass(frozen=True, slots=True)
class ExchangeSizes:
    """CREATE_CHILD_SA and baseline message sizes for one pair of endpoints.

    Track B's PFS inference (LLD section 7.4) works on the *size delta* between
    a Child SA rekey that carried a fresh key exchange and one that did not, so
    it needs both series and neither is an SA payload -- which is why they are
    collected here rather than folded into ``IkeNegotiation``, whose every
    field describes a negotiation's *contents*.

    Grouped by endpoint pair rather than by IKE SPI on purpose: an IKE SA that
    rekeys itself changes SPI, and the CREATE_CHILD_SA exchanges before and
    after that are the same tunnel's rekeys and belong in one series.
    """

    src: str
    dst: str
    create_child: tuple[int, ...]
    baseline: tuple[int, ...]

    def matches(self, src: str, dst: str) -> bool:
        return {self.src, self.dst} == {src, dst}


def exchange_sizes(messages: Sequence[IsakmpMessage]) -> list[ExchangeSizes]:
    """Collect per-endpoint-pair CREATE_CHILD_SA and INFORMATIONAL sizes.

    INFORMATIONAL is the baseline because it is the one IKEv2 exchange that
    never carries a KE payload and is routinely present -- every tunnel this
    testbed tears down sends a DELETE inside one. A capture with no
    INFORMATIONAL exchange yields an empty baseline, and ``infer_pfs`` reports
    UNAVAILABLE with that reason rather than measuring against nothing.

    IKEv1 is absent by construction: it has no CREATE_CHILD_SA, its Quick Mode
    rekeys are encrypted, and LLD section 7.4's method does not apply to them.
    """
    grouped: dict[tuple[str, str], tuple[list[int], list[int]]] = {}
    for message in messages:
        if message.ike_version is not IkeVersion.IKEV2 or not message.length:
            continue
        key = (
            (message.src, message.dst)
            if message.src <= message.dst
            else (
                message.dst,
                message.src,
            )
        )
        create_child, baseline = grouped.setdefault(key, ([], []))
        if message.exchange_type == IKE_EXCHANGE_TYPE_CREATE_CHILD_SA:
            create_child.append(message.length)
        elif message.exchange_type == IKE_EXCHANGE_TYPE_INFORMATIONAL:
            baseline.append(message.length)

    return [
        ExchangeSizes(src=src, dst=dst, create_child=tuple(create_child), baseline=tuple(baseline))
        for (src, dst), (create_child, baseline) in grouped.items()
    ]

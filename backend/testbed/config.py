"""The testbed session configuration and its ground truth.

Implementation-plan steps 2.2 and 2.7; the matrix dimensions are LLD section
10.1.

Two vocabularies meet in this module and it is worth being explicit about which
is which, because conflating them is how a dataset ends up mislabelled.

*Matrix labels* -- ``aes128gcm16``, ``ikev1-aggressive``, ``v6`` -- are the
shorthand the testbed uses for itself. They are convenient, they happen to
coincide with the proposal keywords strongSwan accepts, and they are not part of
the product contract. They live here.

*Contract values* are the ``core.enums`` members that ``SecurityAssociation``
carries. Track A produces them from a capture, and step 4.8 asserts they match
the ground truth of the session. They are defined once in ``core/enums.py`` and
this module maps onto them rather than restating them.

The ground truth therefore records both: what was configured, in matrix terms,
and what a correct parser should report, in contract terms.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from analyzer.core.enums import (
    AuthMethod,
    EncryptionAlg,
    IkeExchangeMode,
    IkeVersion,
    IntegrityAlg,
    OperatingMode,
    PrfAlg,
    TrafficClass,
)


class EspSuite(StrEnum):
    """The ``esp`` dimension of the matrix: a cipher and integrity pair.

    A matrix label, not a contract value -- ``SecurityAssociation`` splits this
    into ``encryption_alg``, ``encryption_keylen`` and ``integrity_alg``, which
    is what ``ESP_SUITES`` below does. The strings match the proposal keywords
    strongSwan accepts, so the rendered config needs no second translation table
    to drift out of step with this one.
    """

    AES128_SHA1 = "aes128-sha1"
    AES256_SHA256 = "aes256-sha256"
    AES128GCM16 = "aes128gcm16"
    AES256GCM16 = "aes256gcm16"
    TRIPLE_DES_SHA1 = "3des-sha1"


class IkeFlavour(StrEnum):
    """The ``ike`` dimension: version and, for IKEv1, Phase 1 exchange mode."""

    IKEV1_MAIN = "ikev1-main"
    IKEV1_AGGRESSIVE = "ikev1-aggressive"
    IKEV2 = "ikev2"


class IpVersion(StrEnum):
    """The ``ip`` dimension."""

    V4 = "v4"
    V6 = "v6"


class EspSuiteSpec(BaseModel):
    """How one ``EspSuite`` decomposes into contract values."""

    model_config = ConfigDict(frozen=True)

    encryption_alg: EncryptionAlg
    encryption_keylen: int
    integrity_alg: IntegrityAlg

    ike_proposal_crypto: str
    """The IKE half of the proposal, without the DH group.

    Deliberately CBC-plus-HMAC even for the AEAD suites. IKEv1 cannot negotiate
    an AEAD cipher for Phase 1 at all, so deriving the IKE proposal from the ESP
    suite directly would make every ``ikev1`` by ``gcm`` cell of the matrix fail
    to negotiate -- and those cells are not hypothetical, they are how a great
    many real deployments are configured. Keeping IKE on CBC and letting ESP
    carry the AEAD is both the portable choice and the realistic one.
    """


ESP_SUITES: Final[dict[EspSuite, EspSuiteSpec]] = {
    EspSuite.AES128_SHA1: EspSuiteSpec(
        encryption_alg=EncryptionAlg.AES_CBC,
        encryption_keylen=128,
        integrity_alg=IntegrityAlg.HMAC_SHA1_96,
        ike_proposal_crypto="aes128-sha1",
    ),
    EspSuite.AES256_SHA256: EspSuiteSpec(
        encryption_alg=EncryptionAlg.AES_CBC,
        encryption_keylen=256,
        integrity_alg=IntegrityAlg.HMAC_SHA256_128,
        ike_proposal_crypto="aes256-sha256",
    ),
    EspSuite.AES128GCM16: EspSuiteSpec(
        encryption_alg=EncryptionAlg.AES_GCM_16,
        encryption_keylen=128,
        # Not UNKNOWN and not "no integrity": an AEAD cipher integrity-protects
        # internally, which core.enums spells NONE as a negotiated absence.
        integrity_alg=IntegrityAlg.NONE,
        ike_proposal_crypto="aes128-sha256",
    ),
    EspSuite.AES256GCM16: EspSuiteSpec(
        encryption_alg=EncryptionAlg.AES_GCM_16,
        encryption_keylen=256,
        integrity_alg=IntegrityAlg.NONE,
        ike_proposal_crypto="aes256-sha256",
    ),
    EspSuite.TRIPLE_DES_SHA1: EspSuiteSpec(
        encryption_alg=EncryptionAlg.TRIPLE_DES_CBC,
        # 3DES-EDE is 168 key bits, of which meet-in-the-middle leaves about
        # 112 effective. IKE reports the former; the assessment engine is where
        # the latter belongs.
        encryption_keylen=168,
        integrity_alg=IntegrityAlg.HMAC_SHA1_96,
        ike_proposal_crypto="3des-sha1",
    ),
}


DH_GROUP_KEYWORDS: Final[dict[int, str]] = {
    2: "modp1024",
    14: "modp2048",
    19: "ecp256",
    20: "ecp384",
}
"""IANA group number to strongSwan proposal keyword, for the ``dh`` dimension."""


IKE_FLAVOURS: Final[dict[IkeFlavour, tuple[IkeVersion, IkeExchangeMode | None]]] = {
    IkeFlavour.IKEV1_MAIN: (IkeVersion.IKEV1, IkeExchangeMode.MAIN),
    IkeFlavour.IKEV1_AGGRESSIVE: (IkeVersion.IKEV1, IkeExchangeMode.AGGRESSIVE),
    # IKEv2 has no exchange-mode concept, so the ground truth says so with None
    # rather than picking a member that would then be asserted against a parser
    # correctly reporting UNAVAILABLE.
    IkeFlavour.IKEV2: (IkeVersion.IKEV2, None),
}


PRF_FOR_INTEGRITY: Final[dict[IntegrityAlg, PrfAlg]] = {
    IntegrityAlg.HMAC_SHA1_96: PrfAlg.HMAC_SHA1,
    IntegrityAlg.HMAC_SHA256_128: PrfAlg.HMAC_SHA256,
}
"""IKEv2 PRF implied by the IKE integrity algorithm.

strongSwan derives the PRF from the integrity algorithm when a proposal does not
name one, so the ground truth has to derive it the same way or step 4.8 compares
against a value that nothing ever configured.
"""


TRAFFIC_LABELS: Final[dict[str, TrafficClass]] = {
    "icmp": TrafficClass.ICMP,
    "web": TrafficClass.WEB,
    "voip": TrafficClass.VOIP,
    "video": TrafficClass.VIDEO,
    "email": TrafficClass.EMAIL,
    "filexfer": TrafficClass.FILE_TRANSFER,
    "messaging": TrafficClass.MESSAGING,
}
"""Matrix ``traffic`` keyword to contract ``TrafficClass``.

LLD section 10.1 spells file transfer ``filexfer`` and the contract spells it
``file_transfer``. ``core/enums.py`` names the matrix loader as the owner of
that mapping, so it is here and nowhere else.
"""

TRAFFIC_KEYWORDS: Final[dict[TrafficClass, str]] = {v: k for k, v in TRAFFIC_LABELS.items()}


class PeerAddressing(BaseModel):
    """The addresses one session runs on, for a single IP version."""

    model_config = ConfigDict(frozen=True)

    subnet: str
    """The bridge network the two containers share, e.g. ``10.10.0.0/24``."""

    left: str
    right: str
    """Outer addresses. What a capture on the bridge sees as src and dst."""

    left_protected: str
    right_protected: str
    """Addresses behind each peer, as ``address/prefix``.

    Tunnel mode needs a subnet behind each gateway, or the inner and outer
    addresses coincide and the capture is indistinguishable from transport mode.
    Transport mode ignores these and uses the outer addresses as its traffic
    selectors.
    """

    left_protected_subnet: str
    right_protected_subnet: str

    def offset(self, index: int) -> PeerAddressing:
        """The same addressing on a different outer subnet.

        Index 0 returns the addresses unchanged, so a single-process run is
        byte-identical to what it produced before sharding existed and every
        existing manifest still resumes.
        """
        if index == 0:
            return self
        if ":" in self.subnet:
            # fd00:10:10::/64 -> fd00:10:10:<index>::/64
            prefix = self.subnet.split("::", 1)[0]
            base = f"{prefix}:{index:x}"
            return self.model_copy(
                update={
                    "subnet": f"{base}::/64",
                    "left": f"{base}::2",
                    "right": f"{base}::3",
                }
            )
        # 10.10.0.0/24 -> 10.10.<index>.0/24
        first, second, _third, _rest = self.subnet.split(".", 3)
        base = f"{first}.{second}.{index}"
        return self.model_copy(
            update={"subnet": f"{base}.0/24", "left": f"{base}.2", "right": f"{base}.3"}
        )


IPV4: Final = PeerAddressing(
    subnet="10.10.0.0/24",
    left="10.10.0.2",
    right="10.10.0.3",
    left_protected="192.168.10.1/24",
    right_protected="192.168.20.1/24",
    left_protected_subnet="192.168.10.0/24",
    right_protected_subnet="192.168.20.0/24",
)

IPV6: Final = PeerAddressing(
    subnet="fd00:10:10::/64",
    left="fd00:10:10::2",
    right="fd00:10:10::3",
    left_protected="fd00:192:168:10::1/64",
    right_protected="fd00:192:168:20::1/64",
    left_protected_subnet="fd00:192:168:10::/64",
    right_protected_subnet="fd00:192:168:20::/64",
)


class SessionConfig(BaseModel):
    """One cell of the matrix: everything needed to run and to label a session.

    Frozen, because the configuration of a session is also its ground truth. A
    config mutated between rendering and labelling would produce a capture whose
    labels describe a tunnel that was never built, and nothing downstream could
    detect it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    """Stable identifier for this configuration. Names the output directory and
    the resume manifest entry (step 2.10), so it must be filesystem-safe."""

    mode: OperatingMode
    ike: IkeFlavour
    esp: EspSuite
    dh: int = Field(description="IANA Diffie-Hellman group number.")
    pfs: bool
    ip: IpVersion = IpVersion.V4
    traffic: TrafficClass

    lifetime_s: int = Field(default=3600, gt=0)
    """Configured SA lifetime.

    Observable from the wire for IKEv1 only. RFC 7296 removed lifetime
    negotiation from IKEv2, where each peer simply expires SAs on local policy
    -- so for an IKEv2 session this value is what we configured, not anything a
    parser could report. ``not_observable_from_ike`` says so explicitly.
    """

    duration_s: int = Field(default=180, gt=0)
    """How long to generate traffic for."""

    psk: str = Field(default="testbed-psk-do-not-reuse", min_length=8)
    """Deliberately weak and deliberately constant.

    This PSK protects nothing: these tunnels carry synthetic traffic between two
    containers on a private bridge and are destroyed minutes later. Holding it
    fixed makes sessions reproducible. It must never be copied into anything
    real, which is what the value says out loud.
    """

    seed: int = 20260903
    """Seeds the traffic generators, so that a session replays identically."""

    address_index: int = Field(default=0, ge=0, le=250)
    """Which outer subnet this session runs on. See ``addressing``.

    Recorded in ``labels.json`` through the ``peers`` block, which carries the
    addresses actually used rather than a constant -- so a capture generated by
    shard 3 is self-describing.
    """

    @model_validator(mode="after")
    def _check_dh_group_known(self) -> SessionConfig:
        if self.dh not in DH_GROUP_KEYWORDS:
            known = ", ".join(str(g) for g in sorted(DH_GROUP_KEYWORDS))
            raise ValueError(
                f"dh group {self.dh} has no strongSwan keyword in DH_GROUP_KEYWORDS "
                f"(known: {known}). Add it there rather than passing the keyword in."
            )
        return self

    @model_validator(mode="after")
    def _check_exchange_mode_matches_version(self) -> SessionConfig:
        # Belt and braces around IKE_FLAVOURS: an IKEv2 session claiming an
        # aggressive exchange mode would produce ground truth that no capture
        # could match, and the mismatch would look like a parser bug.
        if self.ike is IkeFlavour.IKEV2 and self.exchange_mode is not None:
            raise ValueError("IKEv2 has no Phase 1 exchange mode")
        return self

    # --- derived views over the matrix values -------------------------------

    @property
    def suite(self) -> EspSuiteSpec:
        return ESP_SUITES[self.esp]

    @property
    def ike_version(self) -> IkeVersion:
        return IKE_FLAVOURS[self.ike][0]

    @property
    def exchange_mode(self) -> IkeExchangeMode | None:
        return IKE_FLAVOURS[self.ike][1]

    @property
    def addressing(self) -> PeerAddressing:
        """The addresses this session runs on, offset by ``address_index``.

        A Docker bridge network needs a subnet no other network on the daemon is
        using, so two sessions running at the same time cannot both have
        ``10.10.0.0/24``: the second gets "Pool overlaps with other one on this
        address space" and fails outright. Offsetting by index is what lets
        concurrent shards (``--shard I/N``) exist at all.

        Only the *outer* subnet is offset. The protected subnets behind each
        gateway live inside their own network namespaces, so two sessions can
        both use 192.168.10.0/24 without colliding -- and keeping them fixed
        keeps the inner traffic identical across shards, which matters because
        a shard index must not be something a classifier could learn.
        """
        base = IPV4 if self.ip is IpVersion.V4 else IPV6
        return base.offset(self.address_index)

    @property
    def dh_keyword(self) -> str:
        return DH_GROUP_KEYWORDS[self.dh]

    @property
    def ike_proposal(self) -> str:
        """The IKE (Phase 1) proposal string for swanctl."""
        return f"{self.suite.ike_proposal_crypto}-{self.dh_keyword}"

    @property
    def esp_proposal(self) -> str:
        """The ESP (Child SA) proposal string for swanctl.

        The DH group appears here only when PFS is on. That is precisely what
        PFS *is* at the wire level -- a fresh key exchange for the Child SA --
        and it is what step 9.4 infers from ``CREATE_CHILD_SA`` message sizes.
        """
        if self.pfs:
            return f"{self.esp.value}-{self.dh_keyword}"
        return self.esp.value

    @property
    def prf_alg(self) -> PrfAlg | None:
        """The PRF strongSwan will derive, or ``None`` where none is negotiated.

        IKEv1 does not negotiate a PRF separately -- it derives one from the
        Phase 1 hash -- so there is nothing for a parser to observe, and the
        ground truth must not claim otherwise.
        """
        if self.ike_version is IkeVersion.IKEV1:
            return None
        integrity = _ike_integrity_alg(self.suite.ike_proposal_crypto)
        return PRF_FOR_INTEGRITY.get(integrity) if integrity else None

    @property
    def is_transport(self) -> bool:
        return self.mode is OperatingMode.TRANSPORT

    def local_ts(self, side: Literal["left", "right"]) -> str:
        """Traffic selector for one side.

        Transport mode protects the addresses of the peers themselves; tunnel
        mode protects the subnets behind them.
        """
        addressing = self.addressing
        if self.is_transport:
            host = addressing.left if side == "left" else addressing.right
            return f"{host}/{128 if self.ip is IpVersion.V6 else 32}"
        if side == "left":
            return addressing.left_protected_subnet
        return addressing.right_protected_subnet

    def remote_ts(self, side: Literal["left", "right"]) -> str:
        return self.local_ts("right" if side == "left" else "left")

    def traffic_endpoint(self, side: Literal["left", "right"]) -> str:
        """The address traffic generators should target on ``side``.

        Transport mode has no protected subnet, so generators talk to the outer
        address. Tunnel mode must use the protected address, or the packets
        never match a policy and leave the host in the clear -- which would
        produce a capture with almost no ESP in it and a label saying otherwise.
        """
        addressing = self.addressing
        if self.is_transport:
            return addressing.left if side == "left" else addressing.right
        protected = addressing.left_protected if side == "left" else addressing.right_protected
        return protected.split("/")[0]

    # --- step 2.7: ground truth ---------------------------------------------

    def to_ground_truth(self, *, image_versions: dict[str, str] | None = None) -> dict[str, Any]:
        """The ``labels.json`` payload for this session.

        Three parts, kept apart on purpose:

        ``dimensions``
            What the matrix chose. Every dimension of LLD section 10.1, in the
            vocabulary of the matrix.
        ``expected``
            What a correct parser should report, keyed by
            ``SecurityAssociation`` field name and valued with contract enums.
            Step 4.8 compares the output of Track A against this directly.
        ``not_observable_from_ike``
            The fields in ``expected`` that no parser can recover from this
            capture, with the reason. Without this list, step 8.2 would flag a
            correctly honest ``UNAVAILABLE`` as a mismatch, and the obvious way
            to make the harness go green would be to teach the parser to guess.
        """
        suite = self.suite
        expected: dict[str, Any] = {
            "ike_version": self.ike_version.value,
            "ike_exchange_mode": self.exchange_mode.value if self.exchange_mode else None,
            "encryption_alg": suite.encryption_alg.value,
            "encryption_keylen": suite.encryption_keylen,
            "integrity_alg": suite.integrity_alg.value,
            "prf_alg": self.prf_alg.value if self.prf_alg else None,
            "dh_group": self.dh,
            "operating_mode": self.mode.value,
            "pfs_enabled": self.pfs,
            "auth_method": AuthMethod.PSK.value,
            "negotiated_lifetime_s": self.lifetime_s,
            "traffic_class": self.traffic.value,
        }

        return {
            "schema_version": "1.0",
            "name": self.name,
            "generated_at": datetime.now(tz=UTC).isoformat(),
            "dimensions": {
                "mode": self.mode.value,
                "ike": self.ike.value,
                "esp": self.esp.value,
                "dh": self.dh,
                "pfs": self.pfs,
                "ip": self.ip.value,
                "traffic": TRAFFIC_KEYWORDS[self.traffic],
                "lifetime_s": self.lifetime_s,
                "duration_s": self.duration_s,
            },
            "expected": expected,
            "not_observable_from_ike": self._unobservable(),
            "proposals": {"ike": self.ike_proposal, "esp": self.esp_proposal},
            "peers": {
                "subnet": self.addressing.subnet,
                "left": self.addressing.left,
                "right": self.addressing.right,
                "left_ts": self.local_ts("left"),
                "right_ts": self.local_ts("right"),
            },
            "image_versions": image_versions or {},
            "seed": self.seed,
        }

    def _unobservable(self) -> dict[str, str]:
        """Fields a correct parser must report as UNAVAILABLE for this config."""
        reasons: dict[str, str] = {
            # PRD section 7, and the SecurityAssociation docstring: tunnel versus
            # transport is carried in no cleartext field, so it is INFERRED even
            # when IKE was captured in full.
            "operating_mode": (
                "not carried in any cleartext IKE field; inferred from "
                "encapsulation overhead (PRD 7, LLD 7.3)"
            ),
        }
        if self.ike_version is IkeVersion.IKEV2:
            reasons["negotiated_lifetime_s"] = (
                "RFC 7296 removed SA lifetime negotiation from IKEv2; each peer "
                "expires on local policy, so no negotiated value exists (LLD 6.4)"
            )
            reasons["auth_method"] = (
                "the IKEv2 AUTH payload sits inside the encrypted IKE_AUTH exchange (LLD 6.2)"
            )
            reasons["ike_exchange_mode"] = "IKEv2 has no Phase 1 exchange mode"
        else:
            reasons["prf_alg"] = (
                "IKEv1 derives the PRF from the Phase 1 hash rather than "
                "negotiating it as a separate transform"
            )
        return reasons


def _ike_integrity_alg(ike_crypto: str) -> IntegrityAlg | None:
    """The integrity algorithm named by an IKE proposal fragment."""
    if ike_crypto.endswith("-sha1"):
        return IntegrityAlg.HMAC_SHA1_96
    if ike_crypto.endswith("-sha256"):
        return IntegrityAlg.HMAC_SHA256_128
    return None


WEAK_REFERENCE: Final = SessionConfig(
    name="weak-reference",
    mode=OperatingMode.TRANSPORT,
    ike=IkeFlavour.IKEV1_AGGRESSIVE,
    esp=EspSuite.TRIPLE_DES_SHA1,
    dh=2,
    pfs=False,
    traffic=TrafficClass.VOIP,
    lifetime_s=86400,
)
"""The weak reference fixture of LLD section 10.1, PRD section 16 demo tunnel 1."""

HARDENED_REFERENCE: Final = SessionConfig(
    name="hardened-reference",
    mode=OperatingMode.TUNNEL,
    ike=IkeFlavour.IKEV2,
    esp=EspSuite.AES256GCM16,
    dh=19,
    pfs=True,
    traffic=TrafficClass.VOIP,
    lifetime_s=3600,
)
"""The hardened reference fixture of LLD section 10.1, PRD section 16 tunnel 2."""

REFERENCE_CONFIGS: Final[dict[str, SessionConfig]] = {
    WEAK_REFERENCE.name: WEAK_REFERENCE,
    HARDENED_REFERENCE.name: HARDENED_REFERENCE,
}

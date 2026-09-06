"""Perfect Forward Secrecy inference. Step 9.4, LLD 7.4.

With the DH group known from ``IKE_SA_INIT``, this is near-deterministic
rather than a threshold guess. A ``CREATE_CHILD_SA`` exchange that performs a
fresh key exchange carries a KE payload whose size is fixed by the group, so
a rekey exchange that is larger than the baseline by roughly that amount did a
fresh DH -- which is what PFS *is* at the wire level.

The honesty requirement here is in the confidence, not the answer. For MODP
groups the delta is 256-384 bytes and unmistakable. For the ECP groups it is
64-96 bytes, which overlaps plausible variation in traffic-selector payload
sizes, so those must carry a materially lower confidence rather than a flat
one. LLD section 7.4 asks for that explicitly, and a reviewer will check it.
"""

from __future__ import annotations

import statistics
from collections.abc import Sequence
from typing import Final

from analyzer.core.schema import Attribute, Evidence

DH_PUBLIC_SIZE: Final[dict[int, int]] = {
    1: 96,  # MODP-768
    2: 128,  # MODP-1024
    5: 192,  # MODP-1536
    14: 256,  # MODP-2048
    15: 384,  # MODP-3072
    16: 512,  # MODP-4096
    19: 64,  # ECP-256
    20: 96,  # ECP-384
    21: 132,  # ECP-521
}
"""Public-value size in bytes, per group. LLD section 7.4's table, extended to
the groups the testbed matrix can produce."""

KE_PAYLOAD_HEADER: Final = 8
"""RFC 7296 section 3.4: 4 bytes of generic payload header plus a 2-byte group
number and 2 reserved bytes."""

MODP_CONFIDENCE: Final = 0.9
"""A 256-byte delta is not something traffic-selector variation produces."""

ECP_CONFIDENCE: Final = 0.65
"""A 64-byte delta is within the range of ordinary payload variation, so this
is deliberately much lower. Reporting ECP PFS at MODP confidence would be the
kind of flat number that invites misplaced trust (PRD section 8.3)."""

ECP_GROUPS: Final[frozenset[int]] = frozenset({19, 20, 21})

MATCH_TOLERANCE: Final = 0.4
"""How far the observed delta may sit from the expected one and still count.
Generous, because the rest of a ``CREATE_CHILD_SA`` varies with traffic
selectors and notify payloads."""


def confidence_for_group(dh_group: int) -> float:
    return ECP_CONFIDENCE if dh_group in ECP_GROUPS else MODP_CONFIDENCE


def infer_pfs(
    create_child_sizes: Sequence[int],
    baseline_sizes: Sequence[int],
    dh_group: int | None,
) -> Attribute[bool]:
    """Whether Child SA rekeys perform a fresh Diffie-Hellman exchange.

    *create_child_sizes* are the encrypted ``CREATE_CHILD_SA`` message sizes;
    *baseline_sizes* are comparable exchanges known not to carry a KE payload
    (informational or delete exchanges), which set the floor to measure from.
    """
    if dh_group is None:
        return Attribute.unavailable(
            "the DH group was not observed, so there is no expected KE payload size "
            "to compare a CREATE_CHILD_SA against (LLD section 7.4)"
        )
    if dh_group not in DH_PUBLIC_SIZE:
        return Attribute.unavailable(
            f"DH group {dh_group} has no known public-value size, so the expected "
            "size delta for a fresh key exchange cannot be computed"
        )
    if not create_child_sizes:
        return Attribute.unavailable(
            "no CREATE_CHILD_SA exchange appears in this capture. For a short "
            "capture of a tunnel with a long rekey interval this is expected, and "
            "it is not evidence either way about PFS (LLD section 7.4)"
        )
    if not baseline_sizes:
        return Attribute.unavailable(
            "no exchange without a key-exchange payload was captured, so there is "
            "no baseline to measure the CREATE_CHILD_SA against"
        )

    baseline = statistics.median(baseline_sizes)
    observed = statistics.median(create_child_sizes)
    delta = observed - baseline
    expected = DH_PUBLIC_SIZE[dh_group] + KE_PAYLOAD_HEADER

    # A KE payload is present if the rekey exchange grew by roughly the size a
    # public value for this group would add.
    enabled = abs(delta - expected) <= expected * MATCH_TOLERANCE

    evidence = Evidence(
        method="create_child_sa_size_delta",
        measured={
            "dh_group": dh_group,
            "expected_delta_bytes": expected,
            "observed_delta_bytes": round(delta),
            "baseline_median_bytes": round(baseline),
            "create_child_median_bytes": round(observed),
            "create_child_exchanges": len(create_child_sizes),
        },
    )

    group_kind = "ECP" if dh_group in ECP_GROUPS else "MODP"
    note = (
        f"a CREATE_CHILD_SA exchange is {round(delta)} bytes larger than the "
        f"baseline; group {dh_group} would add about {expected} bytes for a fresh "
        f"key exchange"
    )
    if dh_group in ECP_GROUPS:
        note += (
            f". Confidence is lower for {group_kind} groups: the delta is small "
            "enough to overlap ordinary traffic-selector variation"
        )

    return Attribute.inferred(enabled, confidence_for_group(dh_group), evidence=evidence, note=note)

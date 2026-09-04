"""Step 1.2 -- the Attribute[T] provenance invariant, proven in both directions.

LLD section 3 calls ``Attribute[T]`` the load-bearing type: it is what makes it
structurally impossible to emit an inferred value without a confidence, or to
dress an inference up as a fact. A validator nobody has tried to break is not an
invariant, so every rule is exercised from both sides here -- the valid
construction succeeds, and the invalid one raises.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from analyzer.core.enums import EncryptionAlg, Provenance
from analyzer.core.schema import MAX_PACKET_INDICES, AnalyzerModel, Attribute, Evidence, UtcDatetime

# --------------------------------------------------------------------------
# The two directions step 1.2 names explicitly
# --------------------------------------------------------------------------


def test_inferred_without_confidence_raises() -> None:
    """An estimate presented without a probability is an estimate dressed as a fact."""
    with pytest.raises(ValidationError, match="inferred attribute requires confidence"):
        Attribute[int](value=256, provenance=Provenance.INFERRED, confidence=None)


def test_observed_with_confidence_raises() -> None:
    """A parsed fact is certain. A confidence on it implies doubt that does not exist."""
    with pytest.raises(ValidationError, match="observed attribute must not carry confidence"):
        Attribute[int](value=256, provenance=Provenance.OBSERVED, confidence=0.9)


# --------------------------------------------------------------------------
# ...and the constructions that must succeed, so the tests above are not
# passing for the trivial reason that everything raises.
# --------------------------------------------------------------------------


def test_inferred_with_confidence_is_accepted() -> None:
    attr = Attribute[EncryptionAlg](
        value=EncryptionAlg.AES_GCM_16,
        provenance=Provenance.INFERRED,
        confidence=0.87,
    )
    assert attr.value is EncryptionAlg.AES_GCM_16
    assert attr.confidence == 0.87


def test_observed_without_confidence_is_accepted() -> None:
    attr = Attribute[int](value=256, provenance=Provenance.OBSERVED)
    assert attr.value == 256
    assert attr.confidence is None


# --------------------------------------------------------------------------
# UNAVAILABLE: the third state, and the one FR-4.9 turns into a guarantee
# --------------------------------------------------------------------------


def test_unavailable_requires_a_note() -> None:
    """LLD section 11.3: unavailable renders as an explicit reason, never a dash.

    A note the model does not require is a note that will not be there when the
    dashboard needs it.
    """
    with pytest.raises(ValidationError, match="unavailable attribute requires a note"):
        Attribute[int](value=None, provenance=Provenance.UNAVAILABLE)


def test_unavailable_rejects_a_whitespace_only_note() -> None:
    with pytest.raises(ValidationError, match="unavailable attribute requires a note"):
        Attribute[int](value=None, provenance=Provenance.UNAVAILABLE, note="   ")


def test_unavailable_must_not_carry_a_value() -> None:
    with pytest.raises(ValidationError, match="unavailable attribute must not carry a value"):
        Attribute[int](value=128, provenance=Provenance.UNAVAILABLE, note="ESP-only capture")


def test_unavailable_must_not_carry_confidence() -> None:
    with pytest.raises(ValidationError, match="unavailable attribute must not carry confidence"):
        Attribute[int](
            value=None,
            provenance=Provenance.UNAVAILABLE,
            confidence=0.4,
            note="ESP-only capture",
        )


def test_unavailable_with_a_note_is_accepted() -> None:
    """FR-4.9, verbatim: AES key length from an ESP-only capture."""
    attr = Attribute[int].unavailable(
        "AES key length is not determinable from ESP alone; no IKE_SA_INIT was captured"
    )
    assert attr.provenance is Provenance.UNAVAILABLE
    assert attr.value is None
    assert attr.confidence is None
    assert attr.note is not None


# --------------------------------------------------------------------------
# Null values may not hide behind a positive provenance
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("provenance", "kwargs"),
    [
        (Provenance.OBSERVED, {}),
        (Provenance.INFERRED, {"confidence": 0.8}),
    ],
)
def test_null_value_requires_unavailable(provenance: Provenance, kwargs: dict[str, float]) -> None:
    """ "Observed: null" is an unavailable value wearing the wrong label."""
    with pytest.raises(ValidationError, match="use UNAVAILABLE if there is none"):
        Attribute[int](value=None, provenance=provenance, **kwargs)


# --------------------------------------------------------------------------
# Confidence bounds
# --------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [-0.01, 1.01, 2.0, -1.0])
def test_confidence_outside_zero_to_one_raises(bad: float) -> None:
    with pytest.raises(ValidationError):
        Attribute[int](value=1, provenance=Provenance.INFERRED, confidence=bad)


@pytest.mark.parametrize("good", [0.0, 0.5, 1.0])
def test_confidence_bounds_are_inclusive(good: float) -> None:
    assert (
        Attribute[int](value=1, provenance=Provenance.INFERRED, confidence=good).confidence == good
    )


# --------------------------------------------------------------------------
# The invariant survives mutation, not just construction
# --------------------------------------------------------------------------


def test_assignment_cannot_break_the_invariant() -> None:
    """Without validate_assignment this is the obvious way round the validator."""
    attr = Attribute[int].observed(256)
    with pytest.raises(ValidationError, match="observed attribute must not carry confidence"):
        attr.confidence = 0.9


def test_assignment_cannot_strip_a_required_confidence() -> None:
    attr = Attribute[int].inferred(256, 0.7)
    with pytest.raises(ValidationError, match="inferred attribute requires confidence"):
        attr.confidence = None


# --------------------------------------------------------------------------
# Constructors
# --------------------------------------------------------------------------


def test_constructors_set_the_right_provenance() -> None:
    assert Attribute[int].observed(2).provenance is Provenance.OBSERVED
    assert Attribute[int].inferred(2, 0.5).provenance is Provenance.INFERRED
    assert Attribute[int].unavailable("no IKE").provenance is Provenance.UNAVAILABLE


def test_unknown_field_is_rejected() -> None:
    """extra="forbid": a typo'd key in a fixture must fail loudly, not vanish."""
    with pytest.raises(ValidationError):
        Attribute[int](value=1, provenance=Provenance.OBSERVED, confidance=0.5)


# --------------------------------------------------------------------------
# Generic parameterisation actually validates
# --------------------------------------------------------------------------


def test_generic_parameter_is_enforced() -> None:
    with pytest.raises(ValidationError):
        Attribute[int](value="not-an-int", provenance=Provenance.OBSERVED)


def test_generic_parameter_coerces_enum_values() -> None:
    attr = Attribute[EncryptionAlg].observed(EncryptionAlg.TRIPLE_DES_CBC)
    assert attr.model_dump(mode="json")["value"] == "3des-cbc"


# --------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------


def test_evidence_requires_a_method() -> None:
    with pytest.raises(ValidationError):
        Evidence(method="")


def test_evidence_defaults_are_not_shared() -> None:
    a, b = Evidence(method="x"), Evidence(method="y")
    a.packet_indices.append(1)
    assert b.packet_indices == []


def test_packet_indices_are_capped() -> None:
    """LLD section 8.4: uncapped, a finding on a million-packet capture kills the
    dashboard. Step 5.8 truncates; the schema refuses anything that did not."""
    Evidence(method="x", packet_indices=list(range(MAX_PACKET_INDICES)))
    with pytest.raises(ValidationError):
        Evidence(method="x", packet_indices=list(range(MAX_PACKET_INDICES + 1)))


def test_total_matching_below_the_listed_indices_raises() -> None:
    with pytest.raises(ValidationError, match="smaller than"):
        Evidence(method="x", packet_indices=[1, 2, 3], total_matching=2)


def test_truncated_evidence_records_the_real_total() -> None:
    ev = Evidence(method="esp_length_lattice", packet_indices=[1, 2, 3], total_matching=412_000)
    assert ev.total_matching == 412_000


# --------------------------------------------------------------------------
# UTC timestamps
# --------------------------------------------------------------------------


class _Stamped(AnalyzerModel):
    at: UtcDatetime


def test_naive_datetime_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _Stamped(at=datetime(2026, 9, 3, 12, 0, 0))  # noqa: DTZ001 -- the point of the test


def test_offset_datetime_is_normalised_to_utc() -> None:
    ist = timezone(timedelta(hours=5, minutes=30))
    model = _Stamped(at=datetime(2026, 9, 3, 17, 30, 0, tzinfo=ist))
    assert model.at == datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)
    assert model.at.utcoffset() == timedelta(0)


def test_datetime_serialises_with_a_trailing_z() -> None:
    """One spelling, so identical input serialises byte-identically (NFR-4)."""
    model = _Stamped(at=datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC))
    assert model.model_dump_json() == '{"at":"2026-09-03T12:00:00Z"}'

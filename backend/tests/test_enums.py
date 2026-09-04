"""Step 1.1 -- every enum LLD section 3 names exists, and is documented.

Also pins the two facts other modules silently depend on: the seven traffic
classes behind the 1/7 chance level in LLD section 8.4, and the category caps
from PRD section 10.1 summing to 100.
"""

from __future__ import annotations

import enum

import pytest

from analyzer.core import enums as e
from analyzer.core.enums import CATEGORY_CAPS, FindingCategory, TrafficClass

# The enums step 1.1 requires, by name.
REQUIRED = [
    "Provenance",
    "IkeVersion",
    "IkeExchangeMode",
    "EncryptionAlg",
    "IntegrityAlg",
    "PrfAlg",
    "OperatingMode",
    "TrafficClass",
    "Severity",
    "FindingCategory",
    "AuthMethod",
]

ALL_ENUMS = [
    obj
    for obj in vars(e).values()
    if isinstance(obj, type) and issubclass(obj, enum.Enum) and obj.__module__ == e.__name__
]


@pytest.mark.parametrize("name", REQUIRED)
def test_required_enum_exists(name: str) -> None:
    assert hasattr(e, name), f"core.enums is missing {name}"
    obj = getattr(e, name)
    assert isinstance(obj, type)
    assert issubclass(obj, enum.Enum)


@pytest.mark.parametrize("name", REQUIRED)
def test_required_enum_has_a_docstring(name: str) -> None:
    """LLD section 1: an enum without a docstring is a value nobody can interpret."""
    doc = getattr(e, name).__doc__
    assert doc is not None
    assert doc.strip(), f"{name} has an empty docstring"


@pytest.mark.parametrize("enum_cls", ALL_ENUMS, ids=lambda c: c.__name__)
def test_values_are_str_and_lowercase(enum_cls: type[enum.Enum]) -> None:
    """Values are the wire format, so they follow the wire convention, not Python's."""
    for member in enum_cls:
        assert isinstance(member.value, str), f"{enum_cls.__name__}.{member.name} is not a str"
        assert member.value == member.value.lower(), (
            f"{enum_cls.__name__}.{member.name} = {member.value!r} is not lowercase"
        )
        assert " " not in member.value, (
            f"{enum_cls.__name__}.{member.name} = {member.value!r} contains a space"
        )


@pytest.mark.parametrize("enum_cls", ALL_ENUMS, ids=lambda c: c.__name__)
def test_values_are_unique(enum_cls: type[enum.Enum]) -> None:
    """Aliases would collapse two distinct wire values into one."""
    values = [m.value for m in enum_cls]
    assert len(values) == len(set(values)), f"{enum_cls.__name__} has duplicate values"


def test_strenum_formats_as_its_value() -> None:
    """The reason for StrEnum over (str, Enum): reports interpolate the value."""
    assert f"{e.Provenance.OBSERVED}" == "observed"
    assert str(e.Severity.CRITICAL) == "critical"


def test_traffic_class_has_exactly_seven_members() -> None:
    """LLD section 8.4 scales metadata exposure from a 1/7 chance level.

    Changing the class count without revisiting that formula silently skews
    every exposure score, so break the build here instead.
    """
    assert len(TrafficClass) == 7


def test_category_caps_cover_every_category() -> None:
    assert set(CATEGORY_CAPS) == set(FindingCategory)


def test_category_caps_sum_to_one_hundred() -> None:
    """PRD section 10.1: the score starts at 100 and the caps must be able to
    consume all of it, but never more."""
    assert sum(CATEGORY_CAPS.values()) == 100


def test_encryption_alg_does_not_encode_aes_key_length() -> None:
    """FR-4.9 depends on this.

    From ESP alone the cipher family is inferable but the AES key length is not
    (PRD section 7, R-4). If a member were named ``aes-256-cbc`` the parser
    could not report the algorithm without also asserting a key length it does
    not know.
    """
    aes_members = [m.value for m in e.EncryptionAlg if m.value.startswith("aes-")]
    assert aes_members, "expected AES members"
    for value in aes_members:
        for keylen in ("128", "192", "256"):
            assert keylen not in value, (
                f"EncryptionAlg.{value} encodes a key length; keep it in encryption_keylen"
            )

"""Policy file schema, loader and validator (LLD 8.1). Steps 5.1-5.2.

A policy is data, not code: NFR-8 requires that adding a compliance rule is a
YAML edit and nothing else. That only holds if the loader is strict, so every
way a rule can be wrong -- an unknown operator, a penalty above its category
cap, a rule keyed on an inference without a confidence guard -- fails at load
with a line reference rather than at evaluation time with a bad report.

The confidence guard (step 5.2) is the important one. LLD section 8.1: "A rule
must not fire on a low-confidence inference." Any rule keyed on an attribute
that can arrive ``INFERRED`` must also carry a ``confidence_gte`` condition on
that same attribute, and this is a *startup* error precisely because the
alternative is a plausible-looking finding derived from a coin flip.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Final, Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from analyzer.core.enums import CATEGORY_CAPS, FindingCategory, Severity
from analyzer.core.schema import AttackTechniqueId, FindingKey, StandardRef


class PolicyError(RuntimeError):
    """The policy file could not be read, parsed, or validated."""


Operator = Literal["eq", "in", "lt", "gt", "confidence_gte"]
"""LLD section 8.1's operator set, exactly. ``all`` and ``any`` are composites
rather than operators and are expressed as their own condition keys."""

ConditionValue = bool | int | float | str

INFERABLE_ATTRIBUTES: Final[frozenset[str]] = frozenset(
    {
        # Track B produces these with a calibrated confidence (PRD section 7).
        "operating_mode",
        "pfs_enabled",
        "replay_sane",
        "observed_rekey_s",
        # Track A produces these as same-family inferences about the Child SA,
        # because the Child SA's own proposal is encrypted for both IKE
        # versions (LLD section 6.4, and step 4.8).
        "encryption_alg",
        "encryption_keylen",
        "integrity_alg",
        "downgrade_available",
    }
)
"""Attributes a rule may not key on without a ``confidence_gte`` guard.

Deliberately a denylist of what *can* be inferred rather than an allowlist of
what is always observed: a new inferred attribute added to the contract without
being listed here would silently escape the guard, whereas a newly-observed
attribute listed here only costs a redundant guard in the policy file.
"""

DERIVED_ATTRIBUTES: Final[frozenset[str]] = frozenset(
    {
        "metadata_exposure_confidence",
        "rekey_observed",
        "sa_duration_s",
    }
)
"""Per-SA values the engine computes rather than reading off the contract.

Not in LLD section 8.1, which only contemplates rules keyed on
``SecurityAssociation`` fields. Three of the step 5.3 rule set cannot be
expressed without them -- ``META-HIGH-EXPOSURE`` needs an aggregate over
``inner_traffic``, and ``KEYMGMT-NO-REKEY-OBSERVED`` needs both whether a rekey
was seen and how long the SA was watched for, since "no rekey in a 3-minute
capture" is not a finding. See ``engine._derived_attributes``.
"""


class Condition(BaseModel):
    """One leaf test, or a composite of them. LLD section 8.1."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    attribute: str | None = None
    operator: Operator | None = None
    value: ConditionValue | None = None
    values: list[ConditionValue] | None = None
    all_of: list[Condition] | None = Field(default=None, alias="all")
    any_of: list[Condition] | None = Field(default=None, alias="any")

    @model_validator(mode="after")
    def _check_shape(self) -> Self:
        is_composite = self.all_of is not None or self.any_of is not None
        is_leaf = self.attribute is not None or self.operator is not None

        if is_composite and is_leaf:
            msg = (
                "a condition is either a leaf (attribute/operator) or a "
                "composite (all/any), not both"
            )
            raise ValueError(msg)
        if self.all_of is not None and self.any_of is not None:
            msg = "a condition may carry `all` or `any`, not both"
            raise ValueError(msg)

        if is_composite:
            branches = self.all_of if self.all_of is not None else self.any_of
            if not branches:
                msg = "a composite condition needs at least one branch"
                raise ValueError(msg)
            return self

        if self.attribute is None or self.operator is None:
            msg = "a leaf condition needs both `attribute` and `operator`"
            raise ValueError(msg)
        if self.operator == "in":
            if self.values is None:
                msg = "operator `in` needs `values`"
                raise ValueError(msg)
        elif self.value is None:
            msg = f"operator `{self.operator}` needs `value`"
            raise ValueError(msg)
        return self

    def referenced_attributes(self) -> set[str]:
        """Every attribute this condition tests, excluding confidence guards."""
        if self.all_of or self.any_of:
            branches = self.all_of or self.any_of or []
            return {a for branch in branches for a in branch.referenced_attributes()}
        if self.operator == "confidence_gte" or self.attribute is None:
            return set()
        return {self.attribute}

    def guarded_attributes(self) -> set[str]:
        """Every attribute this condition carries a ``confidence_gte`` guard for."""
        if self.all_of or self.any_of:
            branches = self.all_of or self.any_of or []
            return {a for branch in branches for a in branch.guarded_attributes()}
        if self.operator == "confidence_gte" and self.attribute is not None:
            return {self.attribute}
        return set()


class Rule(BaseModel):
    """One policy rule. Produces at most one ``Finding`` per SA."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: FindingKey
    category: FindingCategory
    severity: Severity
    penalty: Annotated[int, Field(ge=0, le=100)]
    when: Condition
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    standards: list[StandardRef] = Field(default_factory=list)
    attack: list[AttackTechniqueId] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_penalty_within_cap(self) -> Self:
        cap = CATEGORY_CAPS[self.category]
        if self.penalty > cap:
            msg = (
                f"rule {self.id}: penalty {self.penalty} exceeds the {cap}-point cap "
                f"for category {self.category} (PRD section 10.1)"
            )
            raise ValueError(msg)
        if self.severity is Severity.INFORMATIONAL and self.penalty != 0:
            msg = (
                f"rule {self.id}: an informational finding is an observation, not a "
                f"defect, and must not carry a penalty (got {self.penalty})"
            )
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _check_confidence_guard(self) -> Self:
        """Step 5.2. LLD section 8.1: a rule must not fire on a low-confidence
        inference, and this is a load-time error rather than a runtime one."""
        unguarded = (self.when.referenced_attributes() & INFERABLE_ATTRIBUTES) - (
            self.when.guarded_attributes()
        )
        if unguarded:
            names = ", ".join(sorted(unguarded))
            msg = (
                f"rule {self.id} is keyed on {names}, which can arrive INFERRED, "
                f"without a confidence_gte guard on it. LLD section 8.1: a rule must "
                f"not fire on a low-confidence inference"
            )
            raise ValueError(msg)
        return self


class Policy(BaseModel):
    """A loaded, validated policy file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str = Field(min_length=1)
    profile: str = Field(min_length=1)
    rules: list[Rule] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_unique_ids(self) -> Self:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                msg = f"duplicate rule id {rule.id}"
                raise ValueError(msg)
            seen.add(rule.id)
        return self

    def rule(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)


def _line_of(text: str, needle: str) -> int | None:
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number
    return None


def _describe_validation_error(text: str, exc: ValidationError) -> str:
    """Turn a pydantic error into something with a line number in it.

    A policy file is edited by people who are not reading this loader's source,
    so "rules.3.penalty" alone is not a usable error message.
    """
    parts = []
    for error in exc.errors():
        location = error["loc"]
        line = None
        if len(location) >= 2 and location[0] == "rules" and isinstance(location[1], int):
            rule_index = location[1]
            raw_rules = yaml.safe_load(text).get("rules") or []
            if rule_index < len(raw_rules):
                rule_id = str(raw_rules[rule_index].get("id", ""))
                line = _line_of(text, f"id: {rule_id}") if rule_id else None
        path = ".".join(str(p) for p in location)
        where = f" (line {line})" if line else ""
        parts.append(f"{path}{where}: {error['msg']}")
    return "; ".join(parts)


def load_policy(path: Path) -> Policy:
    """Load and validate a policy file, failing loudly and with a line number."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read policy file {path}: {exc}"
        raise PolicyError(msg) from exc

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        msg = f"{path} is not valid YAML{where}: {getattr(exc, 'problem', exc)}"
        raise PolicyError(msg) from exc

    if not isinstance(raw, dict):
        msg = f"{path}: a policy file must be a mapping with version, profile and rules"
        raise PolicyError(msg)

    try:
        return Policy.model_validate(raw)
    except ValidationError as exc:
        msg = f"{path} failed validation: {_describe_validation_error(text, exc)}"
        raise PolicyError(msg) from exc

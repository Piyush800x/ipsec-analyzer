"""Steps 5.1-5.3: policy schema, the confidence guard, and the baseline file."""

from __future__ import annotations

from pathlib import Path

import pytest

from analyzer.assess.policy import CATEGORY_CAPS, Policy, PolicyError, load_policy

BASELINE = Path(__file__).resolve().parents[1] / "src/analyzer/assess/policies/baseline.yaml"

REQUIRED_RULES = [
    "CRYPTO-3DES",
    "CRYPTO-DES",
    "CRYPTO-NULL-ENC",
    "CRYPTO-WEAK-INTEG-MD5",
    "CRYPTO-SHA1",
    "CRYPTO-DOWNGRADE-OFFER",
    "KEX-WEAK-DH",
    "KEX-PFS-DISABLED",
    "PROTO-IKEV1",
    "PROTO-AGGRESSIVE-MODE",
    "KEYMGMT-LONG-LIFETIME",
    "KEYMGMT-NO-REKEY-OBSERVED",
    "REPLAY-SEQ-ANOMALY",
    "META-HIGH-EXPOSURE",
]


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _minimal_rule(when: str = "{attribute: dh_group, operator: in, values: [1, 2]}") -> str:
    return f"""
version: "1.0"
profile: test
rules:
  - id: TEST-RULE
    category: key_exchange
    severity: high
    penalty: 5
    when: {when}
    title: A title
    description: A description
    remediation: A remediation
"""


# --- step 5.3: the baseline file ------------------------------------------


def test_baseline_policy_loads() -> None:
    policy = load_policy(BASELINE)
    assert isinstance(policy, Policy)
    assert policy.profile == "baseline"


def test_baseline_has_every_required_rule() -> None:
    """Step 5.3's minimum rule set, by name."""
    policy = load_policy(BASELINE)
    assert sorted(rule.id for rule in policy.rules) == sorted(REQUIRED_RULES)


def test_baseline_penalties_are_within_category_caps() -> None:
    """Step 5.3 Done-when: no rule may exceed the PRD section 10.1 cap for its
    own category."""
    for rule in load_policy(BASELINE).rules:
        assert rule.penalty <= CATEGORY_CAPS[rule.category], rule.id


def test_baseline_rules_all_carry_remediation_naming_a_parameter() -> None:
    """FR-5.7: "use stronger crypto" is not remediation."""
    for rule in load_policy(BASELINE).rules:
        assert len(rule.remediation) > 40, rule.id


# --- steps 5.1, 5.2: the loader and its validators -------------------------


def test_malformed_yaml_fails_with_a_line_reference(tmp_path: Path) -> None:
    """Step 5.1 Done-when."""
    path = _write(tmp_path, "version: '1.0'\nprofile: test\nrules:\n  - id: [unclosed\n")
    with pytest.raises(PolicyError, match=r"line \d+"):
        load_policy(path)


def test_schema_error_names_the_offending_rule_line(tmp_path: Path) -> None:
    path = _write(tmp_path, _minimal_rule().replace("severity: high", "severity: catastrophic"))
    with pytest.raises(PolicyError, match=r"line \d+"):
        load_policy(path)


def test_unknown_operator_is_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, _minimal_rule("{attribute: dh_group, operator: matches, value: 2}"))
    with pytest.raises(PolicyError):
        load_policy(path)


def test_penalty_above_category_cap_is_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, _minimal_rule().replace("penalty: 5", "penalty: 99"))
    with pytest.raises(PolicyError, match="cap"):
        load_policy(path)


def test_informational_rule_with_a_penalty_is_rejected(tmp_path: Path) -> None:
    text = _minimal_rule().replace("severity: high", "severity: informational")
    with pytest.raises(PolicyError, match="penalty"):
        load_policy(_write(tmp_path, text))


def test_unguarded_inferable_attribute_is_rejected(tmp_path: Path) -> None:
    """Step 5.2 Done-when: a policy with an unguarded pfs_enabled rule fails to
    load. LLD section 8.1 makes this a startup error, not a runtime one."""
    path = _write(tmp_path, _minimal_rule("{attribute: pfs_enabled, operator: eq, value: false}"))
    with pytest.raises(PolicyError, match="confidence_gte"):
        load_policy(path)


def test_guarded_inferable_attribute_loads(tmp_path: Path) -> None:
    when = (
        "\n      all:\n"
        "        - {attribute: pfs_enabled, operator: eq, value: false}\n"
        "        - {attribute: pfs_enabled, operator: confidence_gte, value: 0.7}"
    )
    policy = load_policy(_write(tmp_path, _minimal_rule(when)))
    assert policy.rules[0].id == "TEST-RULE"


def test_observed_only_attribute_needs_no_guard(tmp_path: Path) -> None:
    """dh_group comes from the IKE SA's own proposal and is never inferred."""
    policy = load_policy(_write(tmp_path, _minimal_rule()))
    assert policy.rules[0].id == "TEST-RULE"


def test_duplicate_rule_ids_are_rejected(tmp_path: Path) -> None:
    text = _minimal_rule() + _minimal_rule().split("rules:")[1]
    with pytest.raises(PolicyError, match="duplicate"):
        load_policy(_write(tmp_path, text))


def test_condition_that_is_both_leaf_and_composite_is_rejected(tmp_path: Path) -> None:
    when = (
        "\n      attribute: dh_group\n      operator: eq\n      value: 2\n"
        "      all:\n        - {attribute: dh_group, operator: eq, value: 2}"
    )
    with pytest.raises(PolicyError):
        load_policy(_write(tmp_path, _minimal_rule(when)))


def test_in_operator_without_values_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError):
        load_policy(_write(tmp_path, _minimal_rule("{attribute: dh_group, operator: in}")))


def test_missing_file_is_a_policy_error(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(tmp_path / "nope.yaml")


def test_non_mapping_policy_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="mapping"):
        load_policy(_write(tmp_path, "- just\n- a\n- list\n"))

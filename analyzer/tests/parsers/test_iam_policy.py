from pathlib import Path

import pytest

from src.parsers.exceptions import ParserError
from src.parsers.iam_policy import parse_iam_policy

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_parses_iam_statement_into_one_rule_per_action():
    raw = (FIXTURES / "iam_policy_valid.json").read_bytes()
    rules = parse_iam_policy(raw)

    assert len(rules) == 3
    read_rules = [r for r in rules if r.action == "allow"]
    assert len(read_rules) == 2
    assert {r.tags["iam_action"] for r in read_rules} == {"s3:GetObject", "s3:ListBucket"}


def test_maps_effect_to_action_field():
    raw = (FIXTURES / "iam_policy_valid.json").read_bytes()
    rules = parse_iam_policy(raw)

    deny_rule = next(r for r in rules if r.action == "deny")
    assert deny_rule.tags["iam_action"] == "s3:DeleteBucket"
    assert deny_rule.source_type == "iam_policy"


def test_endpoints_use_principal_type():
    raw = (FIXTURES / "iam_policy_valid.json").read_bytes()
    rules = parse_iam_policy(raw)

    allow_rule = next(r for r in rules if r.action == "allow")
    assert allow_rule.source.type == "principal"
    assert allow_rule.source.value == "*"
    assert allow_rule.destination.type == "principal"
    assert allow_rule.destination.value == "arn:aws:s3:::example-bucket/*"


def test_defaults_principal_to_wildcard_when_absent():
    raw = (FIXTURES / "iam_policy_valid.json").read_bytes()
    rules = parse_iam_policy(raw)

    deny_rule = next(r for r in rules if r.action == "deny")
    assert deny_rule.source.value == "*"


def test_rejects_missing_statement_key():
    with pytest.raises(ParserError, match="'Statement'"):
        parse_iam_policy(b'{"Version": "2012-10-17"}')


def test_rejects_oversized_file():
    raw = b'{"Statement": [' + b"1" * (10 * 1024 * 1024 + 1) + b"]}"
    with pytest.raises(ParserError, match="exceeds maximum size"):
        parse_iam_policy(raw)

from pathlib import Path

import pytest

from src.parsers import parse_policy
from src.parsers.exceptions import ParserError

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_dispatches_to_security_group_parser():
    raw = (FIXTURES / "aws_security_group_valid.json").read_bytes()
    rules = parse_policy(raw, "security_group")
    assert len(rules) == 4


def test_dispatches_to_firewall_parser():
    raw = (FIXTURES / "firewall_valid.yaml").read_bytes()
    rules = parse_policy(raw, "firewall")
    assert len(rules) == 3


def test_dispatches_to_iam_parser():
    raw = (FIXTURES / "iam_policy_valid.json").read_bytes()
    rules = parse_policy(raw, "iam_policy")
    assert len(rules) == 3


def test_rejects_unknown_source_type():
    with pytest.raises(ParserError, match="Unsupported source_type"):
        parse_policy(b"{}", "unknown_type")

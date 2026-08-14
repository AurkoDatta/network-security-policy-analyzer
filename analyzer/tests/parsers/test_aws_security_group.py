from pathlib import Path

import pytest

from src.parsers.aws_security_group import parse_aws_security_group
from src.parsers.exceptions import ParserError

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_parses_valid_security_group_into_normalized_rules():
    raw = (FIXTURES / "aws_security_group_valid.json").read_bytes()
    rules = parse_aws_security_group(raw)

    assert len(rules) == 4
    ssh_rule = next(r for r in rules if r.port_range and r.port_range.start == 22)
    assert ssh_rule.source_type == "security_group"
    assert ssh_rule.source_id == "sg-0123456789abcdef0"
    assert ssh_rule.protocol == "tcp"
    assert ssh_rule.direction == "ingress"
    assert ssh_rule.action == "allow"
    assert ssh_rule.source.type == "cidr"
    assert ssh_rule.source.value == "0.0.0.0/0"
    assert ssh_rule.description == "SSH from anywhere"


def test_splits_dual_stack_rule_into_separate_endpoints():
    raw = (FIXTURES / "aws_security_group_valid.json").read_bytes()
    rules = parse_aws_security_group(raw)

    https_rules = [r for r in rules if r.port_range and r.port_range.start == 443]
    assert len(https_rules) == 2
    values = {r.source.value for r in https_rules}
    assert values == {"10.0.0.0/8", "::/0"}


def test_parses_egress_rule_with_any_protocol():
    raw = (FIXTURES / "aws_security_group_valid.json").read_bytes()
    rules = parse_aws_security_group(raw)

    egress = next(r for r in rules if r.direction == "egress")
    assert egress.protocol == "any"
    assert egress.port_range is None


def test_rejects_malformed_json():
    raw = (FIXTURES / "aws_security_group_malformed.json").read_bytes()
    with pytest.raises(ParserError):
        parse_aws_security_group(raw)


def test_rejects_oversized_file():
    raw = b"[" + b"1" * (10 * 1024 * 1024 + 1) + b"]"
    with pytest.raises(ParserError, match="exceeds maximum size"):
        parse_aws_security_group(raw)


def test_parses_single_group_object_not_wrapped_in_a_list():
    raw = b"""
    {
      "GroupId": "sg-single",
      "IpPermissions": [
        { "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{ "CidrIp": "0.0.0.0/0" }] }
      ]
    }
    """
    rules = parse_aws_security_group(raw)
    assert len(rules) == 1
    assert rules[0].source_id == "sg-single"


def test_parses_security_group_source_endpoint():
    raw = b"""
    [
      {
        "GroupId": "sg-referrer",
        "IpPermissions": [
          {
            "IpProtocol": "tcp",
            "FromPort": 5432,
            "ToPort": 5432,
            "UserIdGroupPairs": [{ "GroupId": "sg-database" }]
          }
        ]
      }
    ]
    """
    rules = parse_aws_security_group(raw)
    assert len(rules) == 1
    assert rules[0].source.type == "security_group"
    assert rules[0].source.value == "sg-database"


def test_rejects_top_level_non_object_non_list():
    with pytest.raises(ParserError, match="object or a list"):
        parse_aws_security_group(b"42")


def test_rejects_group_missing_group_id():
    with pytest.raises(ParserError, match="GroupId"):
        parse_aws_security_group(b'[{"IpPermissions": []}]')

from pathlib import Path

import pytest

from src.parsers.exceptions import ParserError
from src.parsers.generic_firewall import parse_generic_firewall

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_parses_yaml_firewall_rules():
    raw = (FIXTURES / "firewall_valid.yaml").read_bytes()
    rules = parse_generic_firewall(raw)

    assert len(rules) == 3
    ssh_rule = next(r for r in rules if r.description == "SSH from internal network")
    assert ssh_rule.port_range.start == 22
    assert ssh_rule.port_range.end == 22
    assert ssh_rule.action == "allow"
    assert ssh_rule.source_type == "firewall"


def test_parses_json_firewall_rules():
    raw = (FIXTURES / "firewall_valid.json").read_bytes()
    rules = parse_generic_firewall(raw)

    assert len(rules) == 1
    assert rules[0].tags == {"env": "prod"}


def test_single_port_field_expands_to_start_and_end():
    raw = (FIXTURES / "firewall_valid.yaml").read_bytes()
    rules = parse_generic_firewall(raw)

    telnet_rule = next(r for r in rules if r.action == "deny")
    assert telnet_rule.port_range.start == 23
    assert telnet_rule.port_range.end == 23


def test_missing_port_fields_yields_none_port_range():
    raw = (FIXTURES / "firewall_valid.yaml").read_bytes()
    rules = parse_generic_firewall(raw)

    egress_rule = next(r for r in rules if r.direction == "egress")
    assert egress_rule.port_range is None


def test_rejects_missing_rules_key():
    with pytest.raises(ParserError, match="'rules'"):
        parse_generic_firewall(b'{"not_rules": []}')


def test_rejects_oversized_file():
    raw = b'{"rules": [' + b"1" * (10 * 1024 * 1024 + 1) + b"]}"
    with pytest.raises(ParserError, match="exceeds maximum size"):
        parse_generic_firewall(raw)


def test_rejects_rules_field_that_is_not_a_list():
    with pytest.raises(ParserError, match="must be a list"):
        parse_generic_firewall(b'{"rules": "not-a-list"}')


def test_rejects_rule_missing_source_field():
    raw = b"""
    {
      "rules": [
        {
          "name": "broken",
          "protocol": "tcp",
          "direction": "ingress",
          "destination": { "type": "cidr", "value": "10.0.0.0/8" }
        }
      ]
    }
    """
    with pytest.raises(ParserError, match="missing required field 'source'"):
        parse_generic_firewall(raw)


def test_rejects_rule_missing_protocol_field():
    raw = b"""
    {
      "rules": [
        {
          "name": "broken",
          "direction": "ingress",
          "source": { "type": "cidr", "value": "0.0.0.0/0" },
          "destination": { "type": "cidr", "value": "10.0.0.0/8" }
        }
      ]
    }
    """
    with pytest.raises(ParserError, match="malformed"):
        parse_generic_firewall(raw)

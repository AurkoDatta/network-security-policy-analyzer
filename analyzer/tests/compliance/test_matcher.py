from datetime import datetime

from src.compliance.loader import ComplianceRule, ComplianceMatcher
from src.compliance.matcher import matches
from src.models import Endpoint, NormalizedRule, PortRange


def _rule(**overrides):
    base = dict(
        id="rule-1",
        source_type="firewall",
        source_id="fw-1",
        protocol="tcp",
        port_range=PortRange(start=22, end=22),
        direction="ingress",
        action="allow",
        source=Endpoint(type="cidr", value="0.0.0.0/0"),
        destination=Endpoint(type="cidr", value="10.0.1.0/24"),
        created_at=datetime(2026, 1, 1),
        modified_at=datetime(2026, 1, 1),
    )
    base.update(overrides)
    return NormalizedRule(**base)


def _compliance_rule(**matcher_overrides):
    matcher = ComplianceMatcher(protocol="tcp", ports=[22], source="0.0.0.0/0")
    for key, value in matcher_overrides.items():
        setattr(matcher, key, value)
    return ComplianceRule(
        framework="cis",
        rule_id="CIS-4.1",
        description="No SSH from anywhere",
        matcher=matcher,
        severity="critical",
    )


def test_matches_on_protocol_port_and_cidr_source():
    rule = _rule()
    compliance_rule = _compliance_rule()
    assert matches(rule, compliance_rule) is True


def test_no_match_when_port_outside_range():
    rule = _rule(port_range=PortRange(start=443, end=443))
    compliance_rule = _compliance_rule()
    assert matches(rule, compliance_rule) is False


def test_no_match_when_source_not_contained_in_cidr():
    rule = _rule(source=Endpoint(type="cidr", value="0.0.0.0/0"))
    compliance_rule = _compliance_rule(source="192.168.1.0/24")
    assert matches(rule, compliance_rule) is False


def test_matches_when_source_is_narrower_cidr_within_matcher():
    rule = _rule(source=Endpoint(type="cidr", value="0.0.0.0/0"))
    compliance_rule = _compliance_rule(source="0.0.0.0/0")
    assert matches(rule, compliance_rule) is True


def test_no_protocol_in_matcher_matches_any_protocol():
    rule = _rule(protocol="udp")
    compliance_rule = _compliance_rule(protocol=None)
    assert matches(rule, compliance_rule) is True


def test_no_match_when_rule_has_no_port_range_but_matcher_requires_port():
    rule = _rule(port_range=None)
    compliance_rule = _compliance_rule()
    assert matches(rule, compliance_rule) is False


def test_no_match_when_protocol_differs():
    rule = _rule(protocol="udp")
    compliance_rule = _compliance_rule()
    assert matches(rule, compliance_rule) is False


def test_no_match_when_destination_not_contained_in_cidr():
    rule = _rule(destination=Endpoint(type="cidr", value="10.0.1.0/24"))
    compliance_rule = _compliance_rule(destination="192.168.1.0/24")
    assert matches(rule, compliance_rule) is False


def test_cidr_matches_falls_back_to_string_equality_on_invalid_cidr():
    rule = _rule(source=Endpoint(type="cidr", value="not-a-cidr"))
    compliance_rule = _compliance_rule(source="not-a-cidr")
    assert matches(rule, compliance_rule) is True

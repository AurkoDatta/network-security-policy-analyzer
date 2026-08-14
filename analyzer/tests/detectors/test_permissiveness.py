from datetime import datetime

from src.detectors.permissiveness import detect_permissiveness
from src.models import Endpoint, NormalizedRule, PortRange


def _rule(**overrides):
    base = dict(
        id="rule-1",
        source_type="firewall",
        source_id="fw-1",
        protocol="tcp",
        port_range=PortRange(start=443, end=443),
        direction="ingress",
        action="allow",
        source=Endpoint(type="cidr", value="10.0.0.0/8"),
        destination=Endpoint(type="cidr", value="10.0.1.0/24"),
        created_at=datetime(2026, 1, 1),
        modified_at=datetime(2026, 1, 1),
    )
    base.update(overrides)
    return NormalizedRule(**base)


def test_detect_permissiveness_any_ipv4():
    rule = _rule(source=Endpoint(type="cidr", value="0.0.0.0/0"))
    result = detect_permissiveness(rule)
    assert result.is_permissive is True
    assert "0.0.0.0/0" in result.reason


def test_detect_permissiveness_any_ipv6():
    rule = _rule(source=Endpoint(type="cidr", value="::/0"))
    result = detect_permissiveness(rule)
    assert result.is_permissive is True
    assert "::/0" in result.reason


def test_detect_permissiveness_any_protocol():
    rule = _rule(protocol="any")
    result = detect_permissiveness(rule)
    assert result.is_permissive is True
    assert "any protocol" in result.reason


def test_detect_permissiveness_full_port_range():
    rule = _rule(port_range=PortRange(start=0, end=65535))
    result = detect_permissiveness(rule)
    assert result.is_permissive is True
    assert "all ports" in result.reason


def test_detect_permissiveness_negative_for_scoped_rule():
    rule = _rule()
    result = detect_permissiveness(rule)
    assert result.is_permissive is False
    assert result.reason == ""


def test_detect_permissiveness_ignores_non_cidr_endpoints():
    rule = _rule(source=Endpoint(type="security_group", value="sg-123"))
    result = detect_permissiveness(rule)
    assert result.is_permissive is False

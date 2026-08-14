from datetime import datetime

from src.detectors.orphaned import detect_orphaned
from src.models import Endpoint, NormalizedRule, PortRange


def _rule(**overrides):
    base = dict(
        id="rule-1",
        source_type="firewall",
        source_id="fw-1",
        protocol="tcp",
        port_range=PortRange(start=8080, end=8080),
        direction="ingress",
        action="allow",
        source=Endpoint(type="cidr", value="10.0.0.0/8"),
        destination=Endpoint(type="cidr", value="10.0.1.0/24"),
        created_at=datetime(2024, 1, 1),
        modified_at=datetime(2024, 1, 1),
        description="",
    )
    base.update(overrides)
    return NormalizedRule(**base)


def test_flags_stale_undocumented_rule_as_orphaned():
    rule = _rule()
    result = detect_orphaned(rule, as_of=datetime(2026, 1, 1))
    assert result.is_orphaned is True
    assert "180 days" in result.reason


def test_does_not_flag_recently_modified_rule():
    rule = _rule(modified_at=datetime(2025, 12, 1))
    result = detect_orphaned(rule, as_of=datetime(2026, 1, 1))
    assert result.is_orphaned is False


def test_does_not_flag_documented_stale_rule():
    rule = _rule(description="Required for partner VPN tunnel")
    result = detect_orphaned(rule, as_of=datetime(2026, 1, 1))
    assert result.is_orphaned is False


def test_respects_custom_staleness_threshold():
    rule = _rule(modified_at=datetime(2025, 11, 1))
    result = detect_orphaned(rule, as_of=datetime(2026, 1, 1), staleness_days=30)
    assert result.is_orphaned is True

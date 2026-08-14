from datetime import datetime

from src.detectors.conflicts import detect_conflicts
from src.models import Endpoint, NormalizedRule, PortRange


def _rule(rule_id, port_start, port_end, action, **overrides):
    base = dict(
        id=rule_id,
        source_type="firewall",
        source_id="fw-1",
        protocol="tcp",
        port_range=PortRange(start=port_start, end=port_end),
        direction="ingress",
        action=action,
        source=Endpoint(type="cidr", value="0.0.0.0/0"),
        destination=Endpoint(type="cidr", value="10.0.1.0/24"),
        created_at=datetime(2026, 1, 1),
        modified_at=datetime(2026, 1, 1),
    )
    base.update(overrides)
    return NormalizedRule(**base)


def test_detect_conflict_shadowing():
    rule1 = _rule("r1", 22, 22, "allow")
    rule2 = _rule("r2", 20, 25, "deny")
    conflicts = detect_conflicts([rule1, rule2])
    assert any(c.type == "shadowing" for c in conflicts)


def test_detect_conflict_redundancy():
    rule1 = _rule("r1", 443, 443, "allow")
    rule2 = _rule("r2", 443, 443, "allow")
    conflicts = detect_conflicts([rule1, rule2])
    assert len(conflicts) == 1
    assert conflicts[0].type == "redundancy"
    assert conflicts[0].rule_id == "r2"
    assert conflicts[0].conflicting_rule_id == "r1"


def test_detect_conflict_contradiction():
    rule1 = _rule("r1", 3389, 3389, "allow")
    rule2 = _rule("r2", 3389, 3389, "deny")
    conflicts = detect_conflicts([rule1, rule2])
    assert len(conflicts) == 1
    assert conflicts[0].type == "contradiction"


def test_no_conflict_when_ports_disjoint():
    rule1 = _rule("r1", 22, 22, "allow")
    rule2 = _rule("r2", 80, 80, "allow")
    conflicts = detect_conflicts([rule1, rule2])
    assert conflicts == []


def test_no_conflict_across_different_directions():
    rule1 = _rule("r1", 22, 22, "allow", direction="ingress")
    rule2 = _rule("r2", 22, 22, "allow", direction="egress")
    conflicts = detect_conflicts([rule1, rule2])
    assert conflicts == []


def test_no_conflict_across_different_destinations():
    rule1 = _rule("r1", 22, 22, "allow", destination=Endpoint(type="cidr", value="10.0.1.0/24"))
    rule2 = _rule("r2", 22, 22, "allow", destination=Endpoint(type="cidr", value="10.0.2.0/24"))
    conflicts = detect_conflicts([rule1, rule2])
    assert conflicts == []


def test_no_conflict_across_different_sources():
    rule1 = _rule("r1", 22, 22, "allow", source=Endpoint(type="cidr", value="10.0.0.0/8"))
    rule2 = _rule("r2", 22, 22, "allow", source=Endpoint(type="cidr", value="192.168.0.0/16"))
    conflicts = detect_conflicts([rule1, rule2])
    assert conflicts == []


def test_no_conflict_across_different_non_any_protocols():
    rule1 = _rule("r1", 22, 22, "allow", protocol="tcp")
    rule2 = _rule("r2", 22, 22, "allow", protocol="udp")
    conflicts = detect_conflicts([rule1, rule2])
    assert conflicts == []


def test_conflict_when_both_port_ranges_are_none():
    rule1 = NormalizedRule(
        id="r1",
        source_type="iam_policy",
        source_id="pol-1",
        protocol="any",
        port_range=None,
        direction="ingress",
        action="allow",
        source=Endpoint(type="principal", value="*"),
        destination=Endpoint(type="principal", value="arn:aws:s3:::bucket"),
        created_at=datetime(2026, 1, 1),
        modified_at=datetime(2026, 1, 1),
    )
    rule2 = rule1.model_copy(update={"id": "r2", "action": "deny"})
    conflicts = detect_conflicts([rule1, rule2])
    assert len(conflicts) == 1
    assert conflicts[0].type == "contradiction"

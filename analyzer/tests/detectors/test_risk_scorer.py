from datetime import datetime

from src.detectors.risk_scorer import score_rules
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
        description="internal service",
    )
    base.update(overrides)
    return NormalizedRule(**base)


def test_low_risk_for_scoped_documented_rules():
    rules = [_rule(modified_at=datetime(2025, 12, 1))]
    score = score_rules(rules, as_of=datetime(2026, 1, 1))
    assert score.overall < 20
    assert score.permissiveness == 0
    assert score.unused == 0


def test_high_permissiveness_score_for_open_cidr():
    rules = [_rule(source=Endpoint(type="cidr", value="0.0.0.0/0"), modified_at=datetime(2025, 12, 1))]
    score = score_rules(rules, as_of=datetime(2026, 1, 1))
    assert score.permissiveness == 100


def test_high_exposure_score_for_critical_port():
    rules = [
        _rule(
            port_range=PortRange(start=22, end=22),
            source=Endpoint(type="cidr", value="0.0.0.0/0"),
            modified_at=datetime(2025, 12, 1),
        )
    ]
    score = score_rules(rules, as_of=datetime(2026, 1, 1))
    assert score.exposure == 100


def test_unused_score_reflects_orphaned_ratio():
    rules = [
        _rule(id="r1", description="", modified_at=datetime(2024, 1, 1)),
        _rule(id="r2", description="documented", modified_at=datetime(2025, 12, 1)),
    ]
    score = score_rules(rules, as_of=datetime(2026, 1, 1))
    assert score.unused == 50


def test_compliance_violations_score_passthrough_ratio():
    rules = [_rule(id="r1"), _rule(id="r2")]
    score = score_rules(rules, as_of=datetime(2026, 1, 1), compliance_violation_count=1)
    assert score.compliance_violations == 50


def test_overall_is_weighted_combination():
    rules = [_rule(source=Endpoint(type="cidr", value="0.0.0.0/0"), modified_at=datetime(2025, 12, 1))]
    score = score_rules(rules, as_of=datetime(2026, 1, 1))
    expected = round(0.35 * score.permissiveness + 0.30 * score.exposure + 0.25 * score.compliance_violations + 0.10 * score.unused)
    assert score.overall == expected


def test_exposure_counts_scoped_rule_on_critical_port():
    rules = [
        _rule(
            port_range=PortRange(start=22, end=22),
            source=Endpoint(type="cidr", value="10.0.0.0/8"),
            modified_at=datetime(2025, 12, 1),
        )
    ]
    score = score_rules(rules, as_of=datetime(2026, 1, 1))
    assert score.permissiveness == 0
    assert score.exposure == 100


def test_exposure_is_zero_when_rule_has_no_port_range():
    rules = [_rule(port_range=None, modified_at=datetime(2025, 12, 1))]
    score = score_rules(rules, as_of=datetime(2026, 1, 1))
    assert score.exposure == 0


def test_empty_ruleset_scores_zero():
    score = score_rules([], as_of=datetime(2026, 1, 1))
    assert score.overall == 0
    assert score.permissiveness == 0
    assert score.exposure == 0
    assert score.unused == 0
    assert score.compliance_violations == 0

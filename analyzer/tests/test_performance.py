"""Performance tests validating the response-time targets published in
CLAUDE.md/README.md: 100 rules <1s, 500 rules <3s, 1000+ rules <5s.
"""
import time
from datetime import datetime, timezone

from src.compliance import load_ruleset, matches
from src.detectors.conflicts import detect_conflicts
from src.detectors.orphaned import detect_orphaned
from src.detectors.permissiveness import detect_permissiveness
from src.detectors.risk_scorer import score_rules
from src.models import Endpoint, NormalizedRule, PortRange


def _generate_rules(count: int) -> list[NormalizedRule]:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rules = []
    for i in range(count):
        rules.append(
            NormalizedRule(
                id=f"rule-{i}",
                source_type="firewall",
                source_id=f"fw-{i % 10}",
                protocol="tcp",
                port_range=PortRange(start=1000 + i, end=1000 + i),
                direction="ingress" if i % 2 == 0 else "egress",
                action="allow" if i % 3 != 0 else "deny",
                source=Endpoint(type="cidr", value=f"10.{i % 256}.0.0/24"),
                destination=Endpoint(type="cidr", value=f"10.{(i + 1) % 256}.0.0/24"),
                created_at=now,
                modified_at=now,
                description=f"rule {i}",
                tags={},
            )
        )
    return rules


def _run_full_analysis(rules: list[NormalizedRule]) -> None:
    as_of = datetime.now(timezone.utc).replace(tzinfo=None)
    for rule in rules:
        detect_permissiveness(rule)
        detect_orphaned(rule, as_of=as_of)
    detect_conflicts(rules)
    ruleset = load_ruleset("cis")
    for rule in rules:
        for compliance_rule in ruleset:
            matches(rule, compliance_rule)
    score_rules(rules, as_of=as_of)


def test_analyzes_100_rules_under_one_second():
    rules = _generate_rules(100)
    start = time.perf_counter()
    _run_full_analysis(rules)
    assert time.perf_counter() - start < 1.0


def test_analyzes_500_rules_under_three_seconds():
    rules = _generate_rules(500)
    start = time.perf_counter()
    _run_full_analysis(rules)
    assert time.perf_counter() - start < 3.0


def test_analyzes_1000_rules_under_five_seconds():
    rules = _generate_rules(1000)
    start = time.perf_counter()
    _run_full_analysis(rules)
    assert time.perf_counter() - start < 5.0

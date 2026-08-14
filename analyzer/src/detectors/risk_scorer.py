"""Combines detector signals into an overall RiskScore.

Weights (permissiveness 35%, exposure 30%, compliance_violations 25%,
unused 10%) are a documented design decision — prompt.txt specifies the
inputs to combine but not exact weights, so exposure and permissiveness
(the signals most directly tied to exploitable misconfiguration) are
weighted highest.
"""
from datetime import datetime

from src.detectors.orphaned import detect_orphaned
from src.detectors.permissiveness import detect_permissiveness
from src.models import NormalizedRule, RiskScore

CRITICAL_PORTS: set[int] = {22, 23, 3389, 5432, 3306, 27017, 6379, 9200, 1433}

_PERMISSIVENESS_WEIGHT = 0.35
_EXPOSURE_WEIGHT = 0.30
_COMPLIANCE_WEIGHT = 0.25
_UNUSED_WEIGHT = 0.10


def _touches_critical_port(rule: NormalizedRule) -> bool:
    if rule.port_range is None:
        return False
    return any(rule.port_range.start <= port <= rule.port_range.end for port in CRITICAL_PORTS)


def score_rules(
    rules: list[NormalizedRule],
    as_of: datetime,
    compliance_violation_count: int = 0,
) -> RiskScore:
    """Score a set of rules across permissiveness, exposure, compliance, and unused axes."""
    if not rules:
        return RiskScore(overall=0, permissiveness=0, exposure=0, compliance_violations=0, unused=0)

    total = len(rules)
    permissive_count = 0
    exposed_count = 0
    orphaned_count = 0

    for rule in rules:
        permissiveness_result = detect_permissiveness(rule)
        if permissiveness_result.is_permissive:
            permissive_count += 1
            if _touches_critical_port(rule):
                exposed_count += 1
        elif _touches_critical_port(rule):
            exposed_count += 1

        orphaned_result = detect_orphaned(rule, as_of=as_of)
        if orphaned_result.is_orphaned:
            orphaned_count += 1

    permissiveness_score = round(100 * permissive_count / total)
    exposure_score = round(100 * exposed_count / total)
    unused_score = round(100 * orphaned_count / total)
    compliance_score = round(100 * compliance_violation_count / total) if total else 0
    compliance_score = min(compliance_score, 100)

    overall = round(
        _PERMISSIVENESS_WEIGHT * permissiveness_score
        + _EXPOSURE_WEIGHT * exposure_score
        + _COMPLIANCE_WEIGHT * compliance_score
        + _UNUSED_WEIGHT * unused_score
    )

    return RiskScore(
        overall=overall,
        permissiveness=permissiveness_score,
        exposure=exposure_score,
        compliance_violations=compliance_score,
        unused=unused_score,
    )

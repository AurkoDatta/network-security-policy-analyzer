"""Detects rule conflicts: shadowing, redundancy, and contradiction.

Rules are compared pairwise in list order (which represents evaluation
priority). For each pair (i, j) with i < j:
  - No overlap in direction/protocol/ports/endpoints -> no conflict.
  - Full equality (direction, protocol, ports, source, destination) and
    same action -> redundancy.
  - Full equality and different action -> contradiction.
  - Overlap but not full equality -> shadowing (rule j is partially
    shadowed by the earlier rule i).
"""
from typing import Literal

from pydantic import BaseModel

from src.models import NormalizedRule


class Conflict(BaseModel):
    type: Literal["shadowing", "redundancy", "contradiction"]
    rule_id: str
    conflicting_rule_id: str
    description: str


def _ports_overlap(a: NormalizedRule, b: NormalizedRule) -> bool:
    if a.port_range is None or b.port_range is None:
        return a.port_range == b.port_range
    return a.port_range.start <= b.port_range.end and b.port_range.start <= a.port_range.end


def _endpoints_equal(a, b) -> bool:
    return a.type == b.type and a.value == b.value


def _rules_overlap(a: NormalizedRule, b: NormalizedRule) -> bool:
    if a.direction != b.direction:
        return False
    if a.protocol != b.protocol and "any" not in (a.protocol, b.protocol):
        return False
    if not _ports_overlap(a, b):
        return False
    if not _endpoints_equal(a.source, b.source):
        return False
    if not _endpoints_equal(a.destination, b.destination):
        return False
    return True


def _fully_equal(a: NormalizedRule, b: NormalizedRule) -> bool:
    return (
        a.direction == b.direction
        and a.protocol == b.protocol
        and a.port_range == b.port_range
        and _endpoints_equal(a.source, b.source)
        and _endpoints_equal(a.destination, b.destination)
    )


def detect_conflicts(rules: list[NormalizedRule]) -> list[Conflict]:
    """Classify pairwise conflicts among rules, treating list order as evaluation priority."""
    conflicts: list[Conflict] = []
    for i in range(len(rules)):
        for j in range(i + 1, len(rules)):
            earlier, later = rules[i], rules[j]
            if not _rules_overlap(earlier, later):
                continue
            if _fully_equal(earlier, later):
                if earlier.action == later.action:
                    conflicts.append(
                        Conflict(
                            type="redundancy",
                            rule_id=later.id,
                            conflicting_rule_id=earlier.id,
                            description=f"Rule '{later.id}' is a duplicate of rule '{earlier.id}'",
                        )
                    )
                else:
                    conflicts.append(
                        Conflict(
                            type="contradiction",
                            rule_id=later.id,
                            conflicting_rule_id=earlier.id,
                            description=(
                                f"Rule '{later.id}' ({later.action}) contradicts "
                                f"rule '{earlier.id}' ({earlier.action}) on identical traffic"
                            ),
                        )
                    )
            else:
                conflicts.append(
                    Conflict(
                        type="shadowing",
                        rule_id=later.id,
                        conflicting_rule_id=earlier.id,
                        description=f"Rule '{later.id}' is partially shadowed by earlier rule '{earlier.id}'",
                    )
                )
    return conflicts

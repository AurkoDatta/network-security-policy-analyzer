"""Heuristic orphaned-rule detector.

No traffic-log ingestion exists yet (see CLAUDE.md open questions), so
orphaned rules are approximated as ones that are both stale (not modified
recently) and undocumented (empty description). `as_of` is injected rather
than read from the clock so results stay deterministic in tests.
"""
from datetime import datetime

from pydantic import BaseModel

from src.models import NormalizedRule


class OrphanedResult(BaseModel):
    is_orphaned: bool
    reason: str


def detect_orphaned(rule: NormalizedRule, as_of: datetime, staleness_days: int = 180) -> OrphanedResult:
    """Flag a rule as orphaned if it is both stale and undocumented."""
    age_days = (as_of - rule.modified_at).days
    is_stale = age_days > staleness_days
    is_undocumented = rule.description.strip() == ""

    if is_stale and is_undocumented:
        return OrphanedResult(
            is_orphaned=True,
            reason=f"Rule has not been modified in {age_days} days (> {staleness_days} days) and has no description",
        )
    return OrphanedResult(is_orphaned=False, reason="")

"""Loads bundled compliance rulesets (CIS/HIPAA/PCI-DSS) and custom rulesets."""
import functools
import json
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel

_RULESETS_DIR = Path(__file__).parent / "rulesets"

_BUNDLED_FRAMEWORKS = {"cis", "hipaa", "pci_dss"}


class ComplianceMatcher(BaseModel):
    protocol: Optional[str] = None
    ports: Optional[list[int]] = None
    source: Optional[str] = None
    destination: Optional[str] = None


class ComplianceRule(BaseModel):
    framework: str
    rule_id: str
    description: str
    matcher: ComplianceMatcher
    severity: Literal["critical", "high", "medium", "low"]


@functools.lru_cache(maxsize=None)
def load_ruleset(framework: str) -> list[ComplianceRule]:
    """Load a bundled compliance ruleset by framework name (cis, hipaa, pci_dss).

    Bundled rulesets never change at runtime, so results are cached for the
    life of the process — repeated analyze calls for the same framework
    don't re-read and re-parse the ruleset JSON file each time.
    """
    if framework not in _BUNDLED_FRAMEWORKS:
        raise ValueError(f"Unknown compliance framework: {framework}")
    path = _RULESETS_DIR / f"{framework}.json"
    data = json.loads(path.read_text())
    return [ComplianceRule(**entry) for entry in data]


def load_custom_ruleset(raw: bytes) -> list[ComplianceRule]:
    """Load and validate a user-supplied custom compliance ruleset from raw JSON bytes."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Custom ruleset could not be parsed as JSON: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError("Custom ruleset must be a JSON array of rule objects")
    return [ComplianceRule(**entry) for entry in data]

"""Detects overly permissive rules: any-CIDR, any-protocol, all-ports."""
from pydantic import BaseModel

from src.models import NormalizedRule

_ANY_IPV4 = "0.0.0.0/0"
_ANY_IPV6 = "::/0"


class PermissivenessResult(BaseModel):
    is_permissive: bool
    reason: str


def detect_permissiveness(rule: NormalizedRule) -> PermissivenessResult:
    """Flag a rule as permissive if it exposes any-CIDR, any-protocol, or all-ports."""
    reasons: list[str] = []

    for endpoint in (rule.source, rule.destination):
        if endpoint.type == "cidr" and endpoint.value == _ANY_IPV4:
            reasons.append(f"endpoint allows any IPv4 address ({_ANY_IPV4})")
        if endpoint.type == "cidr" and endpoint.value == _ANY_IPV6:
            reasons.append(f"endpoint allows any IPv6 address ({_ANY_IPV6})")

    if rule.protocol.lower() == "any":
        reasons.append("rule applies to any protocol")

    if rule.port_range is not None and rule.port_range.start == 0 and rule.port_range.end == 65535:
        reasons.append("rule opens all ports (0-65535)")

    return PermissivenessResult(is_permissive=len(reasons) > 0, reason="; ".join(reasons))

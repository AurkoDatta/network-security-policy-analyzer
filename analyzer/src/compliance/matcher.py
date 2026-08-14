"""Matches NormalizedRule instances against ComplianceRule definitions.

Protocol/port matching is exact; CIDR matching uses stdlib ipaddress to
check whether the rule's endpoint network falls within (or equals) the
compliance matcher's CIDR, so a narrower rule CIDR still matches a
broader compliance-defined network.
"""
import ipaddress

from src.compliance.loader import ComplianceRule
from src.models import NormalizedRule


def _cidr_matches(rule_value: str, matcher_cidr: str) -> bool:
    try:
        rule_network = ipaddress.ip_network(rule_value, strict=False)
        matcher_network = ipaddress.ip_network(matcher_cidr, strict=False)
    except ValueError:
        return rule_value == matcher_cidr
    if rule_network.version != matcher_network.version:
        return False
    return rule_network.subnet_of(matcher_network) or rule_network == matcher_network


def matches(rule: NormalizedRule, compliance_rule: ComplianceRule) -> bool:
    """Return True if `rule` triggers `compliance_rule`'s matcher conditions."""
    matcher = compliance_rule.matcher

    if matcher.protocol is not None and rule.protocol.lower() != matcher.protocol.lower():
        return False

    if matcher.ports is not None:
        if rule.port_range is None:
            return False
        if not any(rule.port_range.start <= port <= rule.port_range.end for port in matcher.ports):
            return False

    if matcher.source is not None:
        if rule.source.type != "cidr" or not _cidr_matches(rule.source.value, matcher.source):
            return False

    if matcher.destination is not None:
        if rule.destination.type != "cidr" or not _cidr_matches(rule.destination.value, matcher.destination):
            return False

    return True

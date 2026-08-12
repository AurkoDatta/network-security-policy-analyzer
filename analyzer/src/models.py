"""Pydantic data models mirroring the shared NormalizedRule contract.

Field names and enum values match api/src/models/NormalizedRule.ts exactly
so JSON payloads pass between the API and analyzer without translation.
"""
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel


class PortRange(BaseModel):
    start: int
    end: int


class Endpoint(BaseModel):
    type: Literal["cidr", "ip", "security_group", "principal"]
    value: str


class NormalizedRule(BaseModel):
    id: str
    source_type: Literal["security_group", "firewall", "iam_policy"]
    source_id: str

    protocol: str
    port_range: Optional[PortRange] = None
    direction: Literal["ingress", "egress"]

    source: Endpoint
    destination: Endpoint

    created_at: datetime
    modified_at: datetime
    description: str = ""
    tags: dict[str, str] = {}


class RiskScore(BaseModel):
    overall: int
    permissiveness: int
    exposure: int
    compliance_violations: int
    unused: int


class Finding(BaseModel):
    type: Literal["overly_permissive", "conflict", "orphaned", "compliance_violation"]
    severity: Literal["critical", "high", "medium", "low"]
    rule_id: str
    description: str
    recommendation: str

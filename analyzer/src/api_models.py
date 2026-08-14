"""Request/response models for the analyzer's HTTP API."""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from src.models import Finding, NormalizedRule, RiskScore


class AnalyzeRequest(BaseModel):
    rules: list[NormalizedRule]
    compliance_frameworks: list[str] = []
    as_of: Optional[datetime] = None


class AnalyzeResponse(BaseModel):
    risk_score: RiskScore
    findings: list[Finding]

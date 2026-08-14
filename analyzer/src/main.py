"""FastAPI entrypoint for the analysis engine."""
from datetime import datetime, timezone

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from src.api_models import AnalyzeRequest, AnalyzeResponse
from src.compliance import load_ruleset, matches
from src.config import settings
from src.detectors.conflicts import detect_conflicts
from src.detectors.orphaned import detect_orphaned
from src.detectors.permissiveness import detect_permissiveness
from src.detectors.risk_scorer import score_rules
from src.models import Finding, NormalizedRule
from src.parsers import parse_policy
from src.parsers.exceptions import ParserError

app = FastAPI(title="Network Security Policy Analyzer - Analysis Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "analyzer"}


@app.post("/parse")
async def parse_endpoint(source_type: str = Form(...), file: UploadFile = File(...)) -> list[NormalizedRule]:
    raw = await file.read()
    try:
        return parse_policy(raw, source_type)
    except ParserError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc


def _build_findings(rules: list[NormalizedRule], as_of: datetime, frameworks: list[str]) -> tuple[list[Finding], int]:
    findings: list[Finding] = []

    for rule in rules:
        permissiveness = detect_permissiveness(rule)
        if permissiveness.is_permissive:
            findings.append(
                Finding(
                    type="overly_permissive",
                    severity="high",
                    rule_id=rule.id,
                    description=permissiveness.reason,
                    recommendation="Restrict the source/destination CIDR and protocol scope of this rule.",
                )
            )
        orphaned = detect_orphaned(rule, as_of=as_of)
        if orphaned.is_orphaned:
            findings.append(
                Finding(
                    type="orphaned",
                    severity="low",
                    rule_id=rule.id,
                    description=orphaned.reason,
                    recommendation="Review this rule and remove it if it is no longer needed.",
                )
            )

    for conflict in detect_conflicts(rules):
        severity = "critical" if conflict.type == "contradiction" else "medium"
        findings.append(
            Finding(
                type="conflict",
                severity=severity,
                rule_id=conflict.rule_id,
                description=conflict.description,
                recommendation="Reorder or remove the conflicting rules so evaluation order matches intent.",
            )
        )

    compliance_violation_count = 0
    for framework in frameworks:
        try:
            ruleset = load_ruleset(framework)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        for rule in rules:
            for compliance_rule in ruleset:
                if matches(rule, compliance_rule):
                    compliance_violation_count += 1
                    findings.append(
                        Finding(
                            type="compliance_violation",
                            severity=compliance_rule.severity,
                            rule_id=rule.id,
                            description=f"{compliance_rule.rule_id}: {compliance_rule.description}",
                            recommendation=f"Modify this rule to comply with {compliance_rule.framework.upper()}.",
                        )
                    )

    return findings, compliance_violation_count


@app.post("/analyze")
def analyze_endpoint(request: AnalyzeRequest) -> AnalyzeResponse:
    as_of = request.as_of or datetime.now(timezone.utc).replace(tzinfo=None)
    findings, compliance_violation_count = _build_findings(request.rules, as_of, request.compliance_frameworks)
    risk_score = score_rules(request.rules, as_of=as_of, compliance_violation_count=compliance_violation_count)
    return AnalyzeResponse(risk_score=risk_score, findings=findings)

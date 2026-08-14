from datetime import datetime, timezone

from fastapi.testclient import TestClient

from src.main import app

client = TestClient(app)


def test_parse_endpoint_returns_normalized_rules():
    files = {"file": ("rules.json", b'{"rules": [{"name": "r1", "protocol": "tcp", "port": 22, "direction": "ingress", "action": "allow", "source": {"type": "cidr", "value": "0.0.0.0/0"}, "destination": {"type": "cidr", "value": "10.0.0.0/8"}}]}')}
    data = {"source_type": "firewall"}
    response = client.post("/parse", files=files, data=data)

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["protocol"] == "tcp"


def test_parse_endpoint_rejects_unsupported_source_type():
    files = {"file": ("rules.json", b"{}")}
    data = {"source_type": "unknown"}
    response = client.post("/parse", files=files, data=data)

    assert response.status_code == 400
    assert "Unsupported source_type" in response.json()["detail"]


def test_parse_endpoint_rejects_malformed_file():
    files = {"file": ("rules.json", b"{not valid")}
    data = {"source_type": "firewall"}
    response = client.post("/parse", files=files, data=data)

    assert response.status_code == 400


def _sample_rule(**overrides):
    base = {
        "id": "rule-1",
        "source_type": "firewall",
        "source_id": "fw-1",
        "protocol": "tcp",
        "port_range": {"start": 22, "end": 22},
        "direction": "ingress",
        "action": "allow",
        "source": {"type": "cidr", "value": "0.0.0.0/0"},
        "destination": {"type": "cidr", "value": "10.0.1.0/24"},
        "created_at": "2024-01-01T00:00:00",
        "modified_at": "2024-01-01T00:00:00",
        "description": "",
        "tags": {},
    }
    base.update(overrides)
    return base


def test_analyze_endpoint_returns_findings_and_risk_score():
    payload = {
        "rules": [_sample_rule()],
        "compliance_frameworks": ["cis"],
        "as_of": "2026-01-01T00:00:00",
    }
    response = client.post("/analyze", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert "risk_score" in body
    assert "findings" in body
    assert any(f["type"] == "overly_permissive" for f in body["findings"])
    assert any(f["type"] == "compliance_violation" for f in body["findings"])


def test_analyze_endpoint_flags_conflicts():
    payload = {
        "rules": [
            _sample_rule(id="r1", action="allow"),
            _sample_rule(id="r2", action="deny"),
        ],
        "compliance_frameworks": [],
        "as_of": "2026-01-01T00:00:00",
    }
    response = client.post("/analyze", json=payload)

    body = response.json()
    assert any(f["type"] == "conflict" for f in body["findings"])


def test_analyze_endpoint_rejects_unknown_compliance_framework():
    payload = {
        "rules": [_sample_rule()],
        "compliance_frameworks": ["nonexistent"],
        "as_of": "2026-01-01T00:00:00",
    }
    response = client.post("/analyze", json=payload)

    assert response.status_code == 400


def test_analyze_endpoint_defaults_as_of_to_now_when_omitted():
    payload = {"rules": [_sample_rule()], "compliance_frameworks": []}
    response = client.post("/analyze", json=payload)

    assert response.status_code == 200

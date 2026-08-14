from datetime import datetime

from src.models import Endpoint, NormalizedRule, PortRange


def _base_kwargs():
    return dict(
        id="rule-1",
        source_type="firewall",
        source_id="fw-1",
        protocol="tcp",
        port_range=PortRange(start=22, end=22),
        direction="ingress",
        source=Endpoint(type="cidr", value="0.0.0.0/0"),
        destination=Endpoint(type="cidr", value="10.0.0.1/32"),
        created_at=datetime(2026, 1, 1),
        modified_at=datetime(2026, 1, 1),
    )


def test_action_defaults_to_allow():
    rule = NormalizedRule(**_base_kwargs())
    assert rule.action == "allow"


def test_action_accepts_deny():
    rule = NormalizedRule(**_base_kwargs(), action="deny")
    assert rule.action == "deny"


def test_action_rejects_invalid_value():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        NormalizedRule(**_base_kwargs(), action="maybe")

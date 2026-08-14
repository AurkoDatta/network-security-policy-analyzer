"""Parser for simplified AWS IAM policy documents."""
from datetime import datetime, timezone

from src.models import Endpoint, NormalizedRule
from src.parsers.exceptions import ParserError, parse_json_or_yaml, validate_size


def _as_list(value) -> list:
    if isinstance(value, list):
        return value
    return [value]


def parse_iam_policy(raw: bytes) -> list[NormalizedRule]:
    """Parse a simplified IAM policy document into NormalizedRule instances.

    Each (Statement, Action) pair becomes one NormalizedRule. Effect maps to
    the rule's action field ('Allow' -> 'allow', 'Deny' -> 'deny').
    """
    validate_size(raw)
    parsed = parse_json_or_yaml(raw)

    if not isinstance(parsed, dict) or "Statement" not in parsed:
        raise ParserError("IAM policy file must be an object with a top-level 'Statement' list")

    statements = _as_list(parsed["Statement"])
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rules: list[NormalizedRule] = []
    for stmt_index, statement in enumerate(statements):
        try:
            effect = statement["Effect"]
            resources = _as_list(statement["Resource"])
            actions = _as_list(statement.get("Action", []))
        except (KeyError, TypeError) as exc:
            raise ParserError(f"IAM statement at index {stmt_index} is malformed: {exc}") from exc

        action_value = "allow" if effect == "Allow" else "deny"
        principal = statement.get("Principal", "*")
        principal_value = principal if isinstance(principal, str) else "*"
        sid = statement.get("Sid", f"statement-{stmt_index}")

        for action_index, iam_action in enumerate(actions):
            for resource in resources:
                rules.append(
                    NormalizedRule(
                        id=f"{sid}-{action_index}-{len(rules)}",
                        source_type="iam_policy",
                        source_id=sid,
                        protocol="any",
                        port_range=None,
                        direction="ingress",
                        action=action_value,
                        source=Endpoint(type="principal", value=principal_value),
                        destination=Endpoint(type="principal", value=resource),
                        created_at=now,
                        modified_at=now,
                        description=statement.get("Sid", ""),
                        tags={"iam_action": iam_action, "iam_effect": effect},
                    )
                )
    return rules

"""Dispatch entry point for all policy file parsers."""
from src.models import NormalizedRule
from src.parsers.aws_security_group import parse_aws_security_group
from src.parsers.exceptions import ParserError
from src.parsers.generic_firewall import parse_generic_firewall
from src.parsers.iam_policy import parse_iam_policy

_PARSERS = {
    "security_group": parse_aws_security_group,
    "firewall": parse_generic_firewall,
    "iam_policy": parse_iam_policy,
}


def parse_policy(raw: bytes, source_type: str) -> list[NormalizedRule]:
    """Parse raw policy file bytes using the parser matching source_type."""
    parser = _PARSERS.get(source_type)
    if parser is None:
        raise ParserError(f"Unsupported source_type: {source_type}")
    return parser(raw)

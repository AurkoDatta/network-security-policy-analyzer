"""Shared exceptions and input validation for policy file parsers."""
import json

import yaml


class ParserError(Exception):
    """Raised when a policy file cannot be safely parsed."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


def validate_size(raw: bytes, max_bytes: int = 10 * 1024 * 1024) -> None:
    """Reject files above max_bytes (default 10MB) before parsing."""
    if len(raw) > max_bytes:
        raise ParserError(
            f"File size {len(raw)} bytes exceeds maximum size of {max_bytes} bytes"
        )


def parse_json_or_yaml(raw: bytes) -> dict | list:
    """Parse raw bytes as JSON, falling back to YAML. Raises ParserError on failure."""
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ParserError(f"File could not be parsed as JSON or YAML: {exc}") from exc
    if parsed is None or isinstance(parsed, str):
        raise ParserError("File could not be parsed as JSON or YAML: empty or invalid content")
    return parsed

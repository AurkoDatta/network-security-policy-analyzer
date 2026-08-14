"""Parser for generic YAML/JSON firewall rule exports.

This format also covers GCP-style firewall rules well enough that a
dedicated GCP parser is not needed (see CLAUDE.md locked decisions).
"""
from datetime import datetime, timezone

from src.models import Endpoint, NormalizedRule, PortRange
from src.parsers.exceptions import ParserError, parse_json_or_yaml, validate_size


def _port_range(entry: dict) -> PortRange | None:
    if "port_start" in entry and "port_end" in entry:
        return PortRange(start=entry["port_start"], end=entry["port_end"])
    if "port" in entry:
        return PortRange(start=entry["port"], end=entry["port"])
    return None


def _endpoint(entry: dict, key: str) -> Endpoint:
    try:
        value = entry[key]
    except KeyError as exc:
        raise ParserError(f"Firewall rule is missing required field '{key}'") from exc
    return Endpoint(type=value["type"], value=value["value"])


def parse_generic_firewall(raw: bytes) -> list[NormalizedRule]:
    """Parse a generic firewall YAML/JSON export into NormalizedRule instances."""
    validate_size(raw)
    parsed = parse_json_or_yaml(raw)

    if not isinstance(parsed, dict) or "rules" not in parsed:
        raise ParserError("Firewall file must be an object with a top-level 'rules' list")

    entries = parsed["rules"]
    if not isinstance(entries, list):
        raise ParserError("Firewall file 'rules' field must be a list")

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rules: list[NormalizedRule] = []
    for index, entry in enumerate(entries):
        try:
            rules.append(
                NormalizedRule(
                    id=entry.get("name", f"firewall-rule-{index}"),
                    source_type="firewall",
                    source_id=entry.get("name", f"firewall-rule-{index}"),
                    protocol=entry["protocol"],
                    port_range=_port_range(entry),
                    direction=entry["direction"],
                    action=entry.get("action", "allow"),
                    source=_endpoint(entry, "source"),
                    destination=_endpoint(entry, "destination"),
                    created_at=now,
                    modified_at=now,
                    description=entry.get("description", ""),
                    tags=entry.get("tags", {}),
                )
            )
        except (KeyError, TypeError) as exc:
            raise ParserError(f"Firewall rule at index {index} is malformed: {exc}") from exc
    return rules

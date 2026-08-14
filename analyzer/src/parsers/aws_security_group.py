"""Parser for AWS Security Group JSON exports (describe-security-groups output)."""
from datetime import datetime, timezone

from src.models import Endpoint, NormalizedRule, PortRange
from src.parsers.exceptions import ParserError, parse_json_or_yaml, validate_size


def _protocol_name(ip_protocol: str) -> str:
    return "any" if ip_protocol == "-1" else ip_protocol.lower()


def _port_range(from_port: int | None, to_port: int | None) -> PortRange | None:
    if from_port is None or to_port is None or from_port == -1 or to_port == -1:
        return None
    return PortRange(start=from_port, end=to_port)


def _endpoints_for_permission(permission: dict) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    for ip_range in permission.get("IpRanges", []):
        endpoints.append(Endpoint(type="cidr", value=ip_range["CidrIp"]))
    for ip_range in permission.get("Ipv6Ranges", []):
        endpoints.append(Endpoint(type="cidr", value=ip_range["CidrIpv6"]))
    for pair in permission.get("UserIdGroupPairs", []):
        endpoints.append(Endpoint(type="security_group", value=pair["GroupId"]))
    return endpoints


def _rules_from_permissions(
    permissions: list[dict],
    group_id: str,
    direction: str,
    now: datetime,
) -> list[NormalizedRule]:
    rules: list[NormalizedRule] = []
    for permission in permissions:
        protocol = _protocol_name(permission.get("IpProtocol", "-1"))
        port_range = _port_range(permission.get("FromPort"), permission.get("ToPort"))
        for endpoint in _endpoints_for_permission(permission):
            description = permission.get("IpRanges", [{}])[0].get("Description", "") if endpoint.type == "cidr" else ""
            source = endpoint if direction == "ingress" else Endpoint(type="security_group", value=group_id)
            destination = Endpoint(type="security_group", value=group_id) if direction == "ingress" else endpoint
            rules.append(
                NormalizedRule(
                    id=f"{group_id}-{direction}-{len(rules)}",
                    source_type="security_group",
                    source_id=group_id,
                    protocol=protocol,
                    port_range=port_range,
                    direction=direction,
                    action="allow",
                    source=source,
                    destination=destination,
                    created_at=now,
                    modified_at=now,
                    description=description,
                    tags={},
                )
            )
    return rules


def parse_aws_security_group(raw: bytes) -> list[NormalizedRule]:
    """Parse an AWS Security Group JSON export into NormalizedRule instances."""
    validate_size(raw)
    parsed = parse_json_or_yaml(raw)

    if isinstance(parsed, dict):
        groups = [parsed]
    elif isinstance(parsed, list):
        groups = parsed
    else:
        raise ParserError("Security group file must contain an object or a list of objects")

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rules: list[NormalizedRule] = []
    for group in groups:
        try:
            group_id = group["GroupId"]
        except (KeyError, TypeError) as exc:
            raise ParserError("Security group entry is missing required field 'GroupId'") from exc
        rules.extend(_rules_from_permissions(group.get("IpPermissions", []), group_id, "ingress", now))
        rules.extend(_rules_from_permissions(group.get("IpPermissionsEgress", []), group_id, "egress", now))
    return rules

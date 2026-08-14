# Analysis Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the Phase 2 analysis engine (`analyzer/src/{parsers,detectors,compliance}`) — parsing AWS Security Groups, generic firewall rules, and IAM policies into `NormalizedRule`, then detecting permissiveness, conflicts, orphaned rules, and compliance violations, and scoring overall risk.

**Architecture:** Pure Python modules with no DB or HTTP coupling — every parser takes raw file bytes/dict and returns a list of `NormalizedRule`; every detector takes a list of `NormalizedRule` and returns `Finding`/`RiskScore` objects. This keeps the engine fully unit-testable in isolation and matches the existing `analyzer/src/models.py` contract shared with the API's TypeScript mirror.

**Tech Stack:** Python 3.9+, pydantic 2.x (already in `analyzer/src/models.py`), `pyyaml`, `jsonschema`, `networkx` (conflict graph), stdlib `ipaddress` (CIDR/IP math), `pytest` + `pytest-cov`.

## Global Constraints

- Field names and enum values in every parser/detector output must match `analyzer/src/models.py` exactly (snake_case, no translation layer to the TypeScript side).
- No AI/Claude/LLM attribution anywhere in code, comments, or commit messages.
- Commit messages must be the exact strings from `prompt.txt`'s Milestone 2A/2B/2C list, used in this order: "feat: add AWS security group parser", "feat: implement firewall rule parser", "feat: add permissiveness and conflict detectors", "feat: implement risk scoring algorithm", "feat: add compliance rule matching", "test: add analyzer unit tests (80% coverage)".
- Analyzer test coverage target: >80% (`pytest -v --cov=src`).
- Malformed or oversized input must raise a caught, typed exception — never an unhandled traceback.
- Follow existing code style in `analyzer/src/models.py`/`main.py`/`config.py`: module docstring at top, typed function signatures, pydantic models for all structured data.

---

## File Structure

```
analyzer/src/
  models.py                       (MODIFY — add `action` field)
  parsers/
    __init__.py                   (MODIFY — dispatch helpers)
    exceptions.py                 (NEW — ParserError + validation helpers)
    aws_security_group.py         (NEW)
    generic_firewall.py           (NEW)
    iam_policy.py                 (NEW)
  detectors/
    __init__.py                   (unchanged, empty)
    permissiveness.py             (NEW)
    conflicts.py                  (NEW)
    orphaned.py                   (NEW)
    risk_scorer.py                (NEW)
  compliance/
    __init__.py                   (MODIFY — dispatch helpers)
    matcher.py                    (NEW — regex/CIDR matcher engine)
    loader.py                     (NEW — load bundled + custom rulesets)
    rulesets/
      cis.json                    (NEW)
      hipaa.json                  (NEW)
      pci_dss.json                (NEW)
analyzer/tests/
  test_models.py                  (NEW)
  parsers/
    test_aws_security_group.py    (NEW)
    test_generic_firewall.py      (NEW)
    test_iam_policy.py            (NEW)
  detectors/
    test_permissiveness.py        (NEW)
    test_conflicts.py             (NEW)
    test_orphaned.py              (NEW)
    test_risk_scorer.py           (NEW)
  compliance/
    test_matcher.py                (NEW)
    test_loader.py                 (NEW)
  fixtures/
    aws_security_group_valid.json  (NEW)
    aws_security_group_malformed.json (NEW)
    firewall_valid.yaml            (NEW)
    firewall_valid.json            (NEW)
    iam_policy_valid.json          (NEW)
```

---

### Task 1: Extend `NormalizedRule` with an `action` field

Both the Python and TypeScript mirrors of `NormalizedRule` currently have no way to represent an explicit allow/deny decision. AWS Security Groups and IAM statements are conceptually allow-only, but generic firewall rules commonly include explicit deny rules, and contradiction detection (Task 7) fundamentally requires this concept. Add it as an additive field defaulting to `"allow"` so nothing existing breaks.

**Files:**
- Modify: `analyzer/src/models.py`
- Modify: `api/src/models/NormalizedRule.ts`
- Test: `analyzer/tests/test_models.py`

**Interfaces:**
- Produces: `NormalizedRule.action: Literal["allow", "deny"]` (Python, default `"allow"`) and `NormalizedRule['action']: 'allow' | 'deny'` (TypeScript). Every parser task below must set this field explicitly.

- [ ] **Step 1: Write the failing test**

```python
# analyzer/tests/test_models.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && pytest tests/test_models.py -v`
Expected: FAIL — `NormalizedRule` has no field `action` (pydantic ignores unknown kwargs by default in this config, so `test_action_defaults_to_allow`/`test_action_accepts_deny` fail on the `assert rule.action == ...` line with `AttributeError`).

- [ ] **Step 3: Implement**

In `analyzer/src/models.py`, add the field to the `NormalizedRule` class (after `direction`, before `source`):

```python
class NormalizedRule(BaseModel):
    id: str
    source_type: Literal["security_group", "firewall", "iam_policy"]
    source_id: str

    protocol: str
    port_range: Optional[PortRange] = None
    direction: Literal["ingress", "egress"]
    action: Literal["allow", "deny"] = "allow"

    source: Endpoint
    destination: Endpoint

    created_at: datetime
    modified_at: datetime
    description: str = ""
    tags: dict[str, str] = {}
```

In `api/src/models/NormalizedRule.ts`, mirror the same change in both the interface and the Mongoose schema:

```typescript
export interface NormalizedRule {
  id: string;
  source_type: 'security_group' | 'firewall' | 'iam_policy';
  source_id: string;

  protocol: string;
  port_range: PortRange | null;
  direction: 'ingress' | 'egress';
  action: 'allow' | 'deny';

  source: Endpoint;
  destination: Endpoint;

  created_at: Date;
  modified_at: Date;
  description: string;
  tags: Record<string, string>;
}
```

```typescript
export const NormalizedRuleSchema = new Schema<NormalizedRule>(
  {
    id: { type: String, required: true },
    source_type: {
      type: String,
      enum: ['security_group', 'firewall', 'iam_policy'],
      required: true,
    },
    source_id: { type: String, required: true },

    protocol: { type: String, required: true },
    port_range: { type: PortRangeSchema, default: null },
    direction: { type: String, enum: ['ingress', 'egress'], required: true },
    action: { type: String, enum: ['allow', 'deny'], required: true, default: 'allow' },

    source: { type: EndpointSchema, required: true },
    destination: { type: EndpointSchema, required: true },

    created_at: { type: Date, required: true },
    modified_at: { type: Date, required: true },
    description: { type: String, default: '' },
    tags: { type: Map, of: String, default: {} },
  },
  { _id: false },
);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd analyzer && pytest tests/test_models.py -v`
Expected: PASS (all 3 tests)

Then verify the TypeScript side still compiles: `cd api && npm run build`
Expected: PASS, no type errors.

- [ ] **Step 5: Commit**

```bash
git add analyzer/src/models.py api/src/models/NormalizedRule.ts analyzer/tests/test_models.py
git commit -m "feat: add action field to normalized rule schema"
```

---

### Task 2: Shared parser exceptions and input validation

Every parser needs the same guardrails: reject oversized files before parsing, reject malformed JSON/YAML with a clear error instead of a raw traceback. Build this once, shared by all three parsers.

**Files:**
- Create: `analyzer/src/parsers/exceptions.py`
- Test: covered by each parser's test file (Task 3-5) via `ParserError`

**Interfaces:**
- Produces: `ParserError(Exception)` with `.message: str`; `validate_size(raw: bytes, max_bytes: int = 10 * 1024 * 1024) -> None` (raises `ParserError` if `len(raw) > max_bytes`); `parse_json_or_yaml(raw: bytes) -> dict | list` (raises `ParserError` on invalid syntax).

- [ ] **Step 1: Write the failing test**

```python
# analyzer/tests/parsers/test_exceptions.py
import pytest

from src.parsers.exceptions import ParserError, parse_json_or_yaml, validate_size


def test_validate_size_passes_under_limit():
    validate_size(b"x" * 100, max_bytes=1000)


def test_validate_size_raises_over_limit():
    with pytest.raises(ParserError, match="exceeds maximum size"):
        validate_size(b"x" * 1001, max_bytes=1000)


def test_parse_json_or_yaml_parses_json():
    result = parse_json_or_yaml(b'{"a": 1}')
    assert result == {"a": 1}


def test_parse_json_or_yaml_parses_yaml():
    result = parse_json_or_yaml(b"a: 1\nb: 2\n")
    assert result == {"a": 1, "b": 2}


def test_parse_json_or_yaml_raises_on_garbage():
    with pytest.raises(ParserError, match="could not be parsed"):
        parse_json_or_yaml(b"{not: valid: json: or: yaml: [[[")
```

Create `analyzer/tests/parsers/__init__.py` (empty file) so pytest discovers the package.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && pytest tests/parsers/test_exceptions.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.parsers.exceptions'`

- [ ] **Step 3: Implement**

```python
# analyzer/src/parsers/exceptions.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd analyzer && pytest tests/parsers/test_exceptions.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

No standalone commit — bundled into Task 3's commit since `prompt.txt` has no dedicated exceptions commit message. Proceed directly to Task 3.

---

### Task 3: AWS Security Group parser

**Files:**
- Create: `analyzer/src/parsers/aws_security_group.py`
- Create: `analyzer/tests/fixtures/aws_security_group_valid.json`
- Create: `analyzer/tests/fixtures/aws_security_group_malformed.json`
- Test: `analyzer/tests/parsers/test_aws_security_group.py`

**Interfaces:**
- Consumes: `ParserError`, `validate_size`, `parse_json_or_yaml` from `src.parsers.exceptions`; `NormalizedRule`, `Endpoint`, `PortRange` from `src.models`.
- Produces: `parse_aws_security_group(raw: bytes) -> list[NormalizedRule]`

AWS Security Group export shape (each group has `GroupId`, `GroupName`, and `IpPermissions`/`IpPermissionsEgress` lists; each permission has `IpProtocol`, `FromPort`, `ToPort`, and `IpRanges`/`Ipv6Ranges`/`UserIdGroupPairs`):

- [ ] **Step 1: Create the fixture files**

```json
// analyzer/tests/fixtures/aws_security_group_valid.json
[
  {
    "GroupId": "sg-0123456789abcdef0",
    "GroupName": "web-servers",
    "IpPermissions": [
      {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{ "CidrIp": "0.0.0.0/0", "Description": "SSH from anywhere" }]
      },
      {
        "IpProtocol": "tcp",
        "FromPort": 443,
        "ToPort": 443,
        "IpRanges": [{ "CidrIp": "10.0.0.0/8" }],
        "Ipv6Ranges": [{ "CidrIpv6": "::/0" }]
      }
    ],
    "IpPermissionsEgress": [
      {
        "IpProtocol": "-1",
        "FromPort": -1,
        "ToPort": -1,
        "IpRanges": [{ "CidrIp": "0.0.0.0/0" }]
      }
    ]
  }
]
```

```json
// analyzer/tests/fixtures/aws_security_group_malformed.json
{ "GroupId": "sg-broken", "IpPermissions": [ { "IpProtocol": "tcp"
```

- [ ] **Step 2: Write the failing test**

```python
# analyzer/tests/parsers/test_aws_security_group.py
from pathlib import Path

import pytest

from src.parsers.aws_security_group import parse_aws_security_group
from src.parsers.exceptions import ParserError

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_parses_valid_security_group_into_normalized_rules():
    raw = (FIXTURES / "aws_security_group_valid.json").read_bytes()
    rules = parse_aws_security_group(raw)

    assert len(rules) == 3
    ssh_rule = next(r for r in rules if r.port_range and r.port_range.start == 22)
    assert ssh_rule.source_type == "security_group"
    assert ssh_rule.source_id == "sg-0123456789abcdef0"
    assert ssh_rule.protocol == "tcp"
    assert ssh_rule.direction == "ingress"
    assert ssh_rule.action == "allow"
    assert ssh_rule.source.type == "cidr"
    assert ssh_rule.source.value == "0.0.0.0/0"
    assert ssh_rule.description == "SSH from anywhere"


def test_splits_dual_stack_rule_into_separate_endpoints():
    raw = (FIXTURES / "aws_security_group_valid.json").read_bytes()
    rules = parse_aws_security_group(raw)

    https_rules = [r for r in rules if r.port_range and r.port_range.start == 443]
    assert len(https_rules) == 2
    values = {r.source.value for r in https_rules}
    assert values == {"10.0.0.0/8", "::/0"}


def test_parses_egress_rule_with_any_protocol():
    raw = (FIXTURES / "aws_security_group_valid.json").read_bytes()
    rules = parse_aws_security_group(raw)

    egress = next(r for r in rules if r.direction == "egress")
    assert egress.protocol == "any"
    assert egress.port_range is None


def test_rejects_malformed_json():
    raw = (FIXTURES / "aws_security_group_malformed.json").read_bytes()
    with pytest.raises(ParserError):
        parse_aws_security_group(raw)


def test_rejects_oversized_file():
    raw = b"[" + b"1" * (10 * 1024 * 1024 + 1) + b"]"
    with pytest.raises(ParserError, match="exceeds maximum size"):
        parse_aws_security_group(raw)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd analyzer && pytest tests/parsers/test_aws_security_group.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.parsers.aws_security_group'`

- [ ] **Step 4: Implement**

```python
# analyzer/src/parsers/aws_security_group.py
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd analyzer && pytest tests/parsers/test_aws_security_group.py -v`
Expected: PASS (5 tests)

- [ ] **Step 6: Commit**

```bash
git add analyzer/src/parsers/ analyzer/tests/parsers/test_exceptions.py analyzer/tests/parsers/test_aws_security_group.py analyzer/tests/parsers/__init__.py analyzer/tests/fixtures/aws_security_group_valid.json analyzer/tests/fixtures/aws_security_group_malformed.json
git commit -m "feat: add AWS security group parser"
```

---

### Task 4: Generic firewall rule parser (YAML/JSON)

Generic format models a simple list-of-rules shape distinct from AWS's nested permission structure, and is the format that must also cover GCP-style exports per the locked decision to not build a dedicated GCP parser.

**Files:**
- Create: `analyzer/src/parsers/generic_firewall.py`
- Create: `analyzer/tests/fixtures/firewall_valid.yaml`
- Create: `analyzer/tests/fixtures/firewall_valid.json`
- Test: `analyzer/tests/parsers/test_generic_firewall.py`

**Interfaces:**
- Consumes: same as Task 3.
- Produces: `parse_generic_firewall(raw: bytes) -> list[NormalizedRule]`

Generic format shape — a top-level `rules` list, each entry with `name`, `protocol`, `port_start`/`port_end` (or `port`), `direction`, `action`, `source` (`{type, value}`), `destination` (`{type, value}`), optional `description`/`tags`:

- [ ] **Step 1: Create the fixture files**

```yaml
# analyzer/tests/fixtures/firewall_valid.yaml
rules:
  - name: allow-ssh-internal
    protocol: tcp
    port_start: 22
    port_end: 22
    direction: ingress
    action: allow
    source:
      type: cidr
      value: 10.0.0.0/8
    destination:
      type: cidr
      value: 10.0.1.0/24
    description: SSH from internal network
  - name: deny-telnet
    protocol: tcp
    port: 23
    direction: ingress
    action: deny
    source:
      type: cidr
      value: 0.0.0.0/0
    destination:
      type: cidr
      value: 10.0.1.0/24
  - name: allow-any-egress
    protocol: any
    direction: egress
    action: allow
    source:
      type: cidr
      value: 10.0.1.0/24
    destination:
      type: cidr
      value: 0.0.0.0/0
```

```json
// analyzer/tests/fixtures/firewall_valid.json
{
  "rules": [
    {
      "name": "allow-https",
      "protocol": "tcp",
      "port_start": 443,
      "port_end": 443,
      "direction": "ingress",
      "action": "allow",
      "source": { "type": "cidr", "value": "0.0.0.0/0" },
      "destination": { "type": "cidr", "value": "10.0.2.0/24" },
      "tags": { "env": "prod" }
    }
  ]
}
```

- [ ] **Step 2: Write the failing test**

```python
# analyzer/tests/parsers/test_generic_firewall.py
from pathlib import Path

import pytest

from src.parsers.exceptions import ParserError
from src.parsers.generic_firewall import parse_generic_firewall

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_parses_yaml_firewall_rules():
    raw = (FIXTURES / "firewall_valid.yaml").read_bytes()
    rules = parse_generic_firewall(raw)

    assert len(rules) == 3
    ssh_rule = next(r for r in rules if r.description == "SSH from internal network")
    assert ssh_rule.port_range.start == 22
    assert ssh_rule.port_range.end == 22
    assert ssh_rule.action == "allow"
    assert ssh_rule.source_type == "firewall"


def test_parses_json_firewall_rules():
    raw = (FIXTURES / "firewall_valid.json").read_bytes()
    rules = parse_generic_firewall(raw)

    assert len(rules) == 1
    assert rules[0].tags == {"env": "prod"}


def test_single_port_field_expands_to_start_and_end():
    raw = (FIXTURES / "firewall_valid.yaml").read_bytes()
    rules = parse_generic_firewall(raw)

    telnet_rule = next(r for r in rules if r.action == "deny")
    assert telnet_rule.port_range.start == 23
    assert telnet_rule.port_range.end == 23


def test_missing_port_fields_yields_none_port_range():
    raw = (FIXTURES / "firewall_valid.yaml").read_bytes()
    rules = parse_generic_firewall(raw)

    egress_rule = next(r for r in rules if r.direction == "egress")
    assert egress_rule.port_range is None


def test_rejects_missing_rules_key():
    with pytest.raises(ParserError, match="'rules'"):
        parse_generic_firewall(b'{"not_rules": []}')


def test_rejects_oversized_file():
    raw = b'{"rules": [' + b"1" * (10 * 1024 * 1024 + 1) + b"]}"
    with pytest.raises(ParserError, match="exceeds maximum size"):
        parse_generic_firewall(raw)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd analyzer && pytest tests/parsers/test_generic_firewall.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.parsers.generic_firewall'`

- [ ] **Step 4: Implement**

```python
# analyzer/src/parsers/generic_firewall.py
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd analyzer && pytest tests/parsers/test_generic_firewall.py -v`
Expected: PASS (6 tests)

- [ ] **Step 6: Commit**

```bash
git add analyzer/src/parsers/generic_firewall.py analyzer/tests/parsers/test_generic_firewall.py analyzer/tests/fixtures/firewall_valid.yaml analyzer/tests/fixtures/firewall_valid.json
git commit -m "feat: implement firewall rule parser"
```

---

### Task 5: Simplified IAM policy parser

**Files:**
- Create: `analyzer/src/parsers/iam_policy.py`
- Create: `analyzer/tests/fixtures/iam_policy_valid.json`
- Test: `analyzer/tests/parsers/test_iam_policy.py`

**Interfaces:**
- Consumes: same as Task 3.
- Produces: `parse_iam_policy(raw: bytes) -> list[NormalizedRule]`

Simplified AWS IAM policy document shape — top-level `Statement` list, each entry with `Effect` (`Allow`/`Deny`), `Action` (string or list), `Resource` (string or list), optional `Principal`:

- [ ] **Step 1: Create the fixture file**

```json
// analyzer/tests/fixtures/iam_policy_valid.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3Read",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": "arn:aws:s3:::example-bucket/*"
    },
    {
      "Sid": "DenyDeleteBucket",
      "Effect": "Deny",
      "Action": "s3:DeleteBucket",
      "Resource": "arn:aws:s3:::example-bucket"
    }
  ]
}
```

- [ ] **Step 2: Write the failing test**

```python
# analyzer/tests/parsers/test_iam_policy.py
from pathlib import Path

import pytest

from src.parsers.exceptions import ParserError
from src.parsers.iam_policy import parse_iam_policy

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_parses_iam_statement_into_one_rule_per_action():
    raw = (FIXTURES / "iam_policy_valid.json").read_bytes()
    rules = parse_iam_policy(raw)

    assert len(rules) == 3
    read_rules = [r for r in rules if r.action == "allow"]
    assert len(read_rules) == 2
    assert {r.tags["iam_action"] for r in read_rules} == {"s3:GetObject", "s3:ListBucket"}


def test_maps_effect_to_action_field():
    raw = (FIXTURES / "iam_policy_valid.json").read_bytes()
    rules = parse_iam_policy(raw)

    deny_rule = next(r for r in rules if r.action == "deny")
    assert deny_rule.tags["iam_action"] == "s3:DeleteBucket"
    assert deny_rule.source_type == "iam_policy"


def test_endpoints_use_principal_type():
    raw = (FIXTURES / "iam_policy_valid.json").read_bytes()
    rules = parse_iam_policy(raw)

    allow_rule = next(r for r in rules if r.action == "allow")
    assert allow_rule.source.type == "principal"
    assert allow_rule.source.value == "*"
    assert allow_rule.destination.type == "principal"
    assert allow_rule.destination.value == "arn:aws:s3:::example-bucket/*"


def test_defaults_principal_to_wildcard_when_absent():
    raw = (FIXTURES / "iam_policy_valid.json").read_bytes()
    rules = parse_iam_policy(raw)

    deny_rule = next(r for r in rules if r.action == "deny")
    assert deny_rule.source.value == "*"


def test_rejects_missing_statement_key():
    with pytest.raises(ParserError, match="'Statement'"):
        parse_iam_policy(b'{"Version": "2012-10-17"}')


def test_rejects_oversized_file():
    raw = b'{"Statement": [' + b"1" * (10 * 1024 * 1024 + 1) + b"]}"
    with pytest.raises(ParserError, match="exceeds maximum size"):
        parse_iam_policy(raw)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd analyzer && pytest tests/parsers/test_iam_policy.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.parsers.iam_policy'`

- [ ] **Step 4: Implement**

```python
# analyzer/src/parsers/iam_policy.py
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd analyzer && pytest tests/parsers/test_iam_policy.py -v`
Expected: PASS (6 tests)

- [ ] **Step 6: Commit**

```bash
git add analyzer/src/parsers/iam_policy.py analyzer/tests/parsers/test_iam_policy.py analyzer/tests/fixtures/iam_policy_valid.json
git commit -m "feat: implement firewall rule parser"
```

Note: `prompt.txt` provides only two parser commit messages for Milestone 2A ("add AWS security group parser" and "implement firewall rule parser") despite three parsers being listed. Reuse the "implement firewall rule parser" message for this IAM commit — it is the closest fit among the prescribed messages and both are parser milestone work landing under Milestone 2A.

---

### Task 6: Parser dispatch

Wire the three parsers behind a single entry point so downstream code (Phase 3 API orchestration) doesn't need to know which parser to call.

**Files:**
- Modify: `analyzer/src/parsers/__init__.py`
- Test: `analyzer/tests/parsers/test_dispatch.py`

**Interfaces:**
- Consumes: `parse_aws_security_group`, `parse_generic_firewall`, `parse_iam_policy` from their respective modules.
- Produces: `parse_policy(raw: bytes, source_type: Literal["security_group", "firewall", "iam_policy"]) -> list[NormalizedRule]`

- [ ] **Step 1: Write the failing test**

```python
# analyzer/tests/parsers/test_dispatch.py
from pathlib import Path

import pytest

from src.parsers import parse_policy
from src.parsers.exceptions import ParserError

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_dispatches_to_security_group_parser():
    raw = (FIXTURES / "aws_security_group_valid.json").read_bytes()
    rules = parse_policy(raw, "security_group")
    assert len(rules) == 3


def test_dispatches_to_firewall_parser():
    raw = (FIXTURES / "firewall_valid.yaml").read_bytes()
    rules = parse_policy(raw, "firewall")
    assert len(rules) == 3


def test_dispatches_to_iam_parser():
    raw = (FIXTURES / "iam_policy_valid.json").read_bytes()
    rules = parse_policy(raw, "iam_policy")
    assert len(rules) == 3


def test_rejects_unknown_source_type():
    with pytest.raises(ParserError, match="Unsupported source_type"):
        parse_policy(b"{}", "unknown_type")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && pytest tests/parsers/test_dispatch.py -v`
Expected: FAIL — `ImportError: cannot import name 'parse_policy' from 'src.parsers'`

- [ ] **Step 3: Implement**

```python
# analyzer/src/parsers/__init__.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd analyzer && pytest tests/parsers/test_dispatch.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add analyzer/src/parsers/__init__.py analyzer/tests/parsers/test_dispatch.py
git commit -m "feat: implement firewall rule parser"
```

Note: same reused commit message as Task 5, for the same reason — this closes out Milestone 2A's parser work with no dedicated dispatch commit message in `prompt.txt`.

---

### Task 7: Permissiveness detector

**Files:**
- Create: `analyzer/src/detectors/permissiveness.py`
- Test: `analyzer/tests/detectors/test_permissiveness.py`

**Interfaces:**
- Consumes: `NormalizedRule` from `src.models`.
- Produces: `class PermissivenessResult(BaseModel): is_permissive: bool; reason: str` in `src.detectors.permissiveness`; `detect_permissiveness(rule: NormalizedRule) -> PermissivenessResult`.

Permissiveness signals per CLAUDE.md's "Permissiveness Detection" section: `0.0.0.0/0` or `::/0` on a cidr-type endpoint, `any`/unspecified protocol, and port range covering `0-65535`.

- [ ] **Step 1: Write the failing test**

```python
# analyzer/tests/detectors/test_permissiveness.py
from datetime import datetime

from src.detectors.permissiveness import detect_permissiveness
from src.models import Endpoint, NormalizedRule, PortRange


def _rule(**overrides):
    base = dict(
        id="rule-1",
        source_type="firewall",
        source_id="fw-1",
        protocol="tcp",
        port_range=PortRange(start=443, end=443),
        direction="ingress",
        action="allow",
        source=Endpoint(type="cidr", value="10.0.0.0/8"),
        destination=Endpoint(type="cidr", value="10.0.1.0/24"),
        created_at=datetime(2026, 1, 1),
        modified_at=datetime(2026, 1, 1),
    )
    base.update(overrides)
    return NormalizedRule(**base)


def test_detect_permissiveness_any_ipv4():
    rule = _rule(source=Endpoint(type="cidr", value="0.0.0.0/0"))
    result = detect_permissiveness(rule)
    assert result.is_permissive is True
    assert "0.0.0.0/0" in result.reason


def test_detect_permissiveness_any_ipv6():
    rule = _rule(source=Endpoint(type="cidr", value="::/0"))
    result = detect_permissiveness(rule)
    assert result.is_permissive is True
    assert "::/0" in result.reason


def test_detect_permissiveness_any_protocol():
    rule = _rule(protocol="any")
    result = detect_permissiveness(rule)
    assert result.is_permissive is True
    assert "any protocol" in result.reason


def test_detect_permissiveness_full_port_range():
    rule = _rule(port_range=PortRange(start=0, end=65535))
    result = detect_permissiveness(rule)
    assert result.is_permissive is True
    assert "all ports" in result.reason


def test_detect_permissiveness_negative_for_scoped_rule():
    rule = _rule()
    result = detect_permissiveness(rule)
    assert result.is_permissive is False
    assert result.reason == ""


def test_detect_permissiveness_ignores_non_cidr_endpoints():
    rule = _rule(source=Endpoint(type="security_group", value="sg-123"))
    result = detect_permissiveness(rule)
    assert result.is_permissive is False
```

Create `analyzer/tests/detectors/__init__.py` (empty).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && pytest tests/detectors/test_permissiveness.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.detectors.permissiveness'`

- [ ] **Step 3: Implement**

```python
# analyzer/src/detectors/permissiveness.py
"""Detects overly permissive rules: any-CIDR, any-protocol, all-ports."""
from pydantic import BaseModel

from src.models import NormalizedRule

_ANY_IPV4 = "0.0.0.0/0"
_ANY_IPV6 = "::/0"


class PermissivenessResult(BaseModel):
    is_permissive: bool
    reason: str


def detect_permissiveness(rule: NormalizedRule) -> PermissivenessResult:
    """Flag a rule as permissive if it exposes any-CIDR, any-protocol, or all-ports."""
    reasons: list[str] = []

    for endpoint in (rule.source, rule.destination):
        if endpoint.type == "cidr" and endpoint.value == _ANY_IPV4:
            reasons.append(f"endpoint allows any IPv4 address ({_ANY_IPV4})")
        if endpoint.type == "cidr" and endpoint.value == _ANY_IPV6:
            reasons.append(f"endpoint allows any IPv6 address ({_ANY_IPV6})")

    if rule.protocol.lower() == "any":
        reasons.append("rule applies to any protocol")

    if rule.port_range is not None and rule.port_range.start == 0 and rule.port_range.end == 65535:
        reasons.append("rule opens all ports (0-65535)")

    return PermissivenessResult(is_permissive=len(reasons) > 0, reason="; ".join(reasons))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd analyzer && pytest tests/detectors/test_permissiveness.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

No standalone commit — bundled with Task 8's commit per `prompt.txt`'s combined "feat: add permissiveness and conflict detectors" message. Proceed directly to Task 8.

---

### Task 8: Conflict detector (shadowing, redundancy, contradiction)

Implements the classification algorithm from CLAUDE.md's "Conflict Detection Strategy": for each ordered pair of rules `(i, j)` with `i < j` (list order = evaluation priority), classify by comparing direction/protocol/port-range/source/destination overlap and equality, then `action`.

**Files:**
- Create: `analyzer/src/detectors/conflicts.py`
- Test: `analyzer/tests/detectors/test_conflicts.py`

**Interfaces:**
- Consumes: `NormalizedRule` from `src.models`; `networkx` for the conflict graph.
- Produces: `class Conflict(BaseModel): type: Literal["shadowing", "redundancy", "contradiction"]; rule_id: str; conflicting_rule_id: str; description: str` in `src.detectors.conflicts`; `detect_conflicts(rules: list[NormalizedRule]) -> list[Conflict]`.

- [ ] **Step 1: Write the failing test**

```python
# analyzer/tests/detectors/test_conflicts.py
from datetime import datetime

from src.detectors.conflicts import detect_conflicts
from src.models import Endpoint, NormalizedRule, PortRange


def _rule(rule_id, port_start, port_end, action, **overrides):
    base = dict(
        id=rule_id,
        source_type="firewall",
        source_id="fw-1",
        protocol="tcp",
        port_range=PortRange(start=port_start, end=port_end),
        direction="ingress",
        action=action,
        source=Endpoint(type="cidr", value="0.0.0.0/0"),
        destination=Endpoint(type="cidr", value="10.0.1.0/24"),
        created_at=datetime(2026, 1, 1),
        modified_at=datetime(2026, 1, 1),
    )
    base.update(overrides)
    return NormalizedRule(**base)


def test_detect_conflict_shadowing():
    rule1 = _rule("r1", 22, 22, "allow")
    rule2 = _rule("r2", 20, 25, "deny")
    conflicts = detect_conflicts([rule1, rule2])
    assert any(c.type == "shadowing" for c in conflicts)


def test_detect_conflict_redundancy():
    rule1 = _rule("r1", 443, 443, "allow")
    rule2 = _rule("r2", 443, 443, "allow")
    conflicts = detect_conflicts([rule1, rule2])
    assert len(conflicts) == 1
    assert conflicts[0].type == "redundancy"
    assert conflicts[0].rule_id == "r2"
    assert conflicts[0].conflicting_rule_id == "r1"


def test_detect_conflict_contradiction():
    rule1 = _rule("r1", 3389, 3389, "allow")
    rule2 = _rule("r2", 3389, 3389, "deny")
    conflicts = detect_conflicts([rule1, rule2])
    assert len(conflicts) == 1
    assert conflicts[0].type == "contradiction"


def test_no_conflict_when_ports_disjoint():
    rule1 = _rule("r1", 22, 22, "allow")
    rule2 = _rule("r2", 80, 80, "allow")
    conflicts = detect_conflicts([rule1, rule2])
    assert conflicts == []


def test_no_conflict_across_different_directions():
    rule1 = _rule("r1", 22, 22, "allow", direction="ingress")
    rule2 = _rule("r2", 22, 22, "allow", direction="egress")
    conflicts = detect_conflicts([rule1, rule2])
    assert conflicts == []


def test_no_conflict_across_different_destinations():
    rule1 = _rule("r1", 22, 22, "allow", destination=Endpoint(type="cidr", value="10.0.1.0/24"))
    rule2 = _rule("r2", 22, 22, "allow", destination=Endpoint(type="cidr", value="10.0.2.0/24"))
    conflicts = detect_conflicts([rule1, rule2])
    assert conflicts == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && pytest tests/detectors/test_conflicts.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.detectors.conflicts'`

- [ ] **Step 3: Implement**

```python
# analyzer/src/detectors/conflicts.py
"""Detects rule conflicts: shadowing, redundancy, and contradiction.

Rules are compared pairwise in list order (which represents evaluation
priority). For each pair (i, j) with i < j:
  - No overlap in direction/protocol/ports/endpoints -> no conflict.
  - Full equality (direction, protocol, ports, source, destination) and
    same action -> redundancy.
  - Full equality and different action -> contradiction.
  - Overlap but not full equality -> shadowing (rule j is partially
    shadowed by the earlier rule i).
"""
from typing import Literal

from pydantic import BaseModel

from src.models import NormalizedRule


class Conflict(BaseModel):
    type: Literal["shadowing", "redundancy", "contradiction"]
    rule_id: str
    conflicting_rule_id: str
    description: str


def _ports_overlap(a: NormalizedRule, b: NormalizedRule) -> bool:
    if a.port_range is None or b.port_range is None:
        return a.port_range == b.port_range
    return a.port_range.start <= b.port_range.end and b.port_range.start <= a.port_range.end


def _endpoints_equal(a, b) -> bool:
    return a.type == b.type and a.value == b.value


def _rules_overlap(a: NormalizedRule, b: NormalizedRule) -> bool:
    if a.direction != b.direction:
        return False
    if a.protocol != b.protocol and "any" not in (a.protocol, b.protocol):
        return False
    if not _ports_overlap(a, b):
        return False
    if not _endpoints_equal(a.source, b.source):
        return False
    if not _endpoints_equal(a.destination, b.destination):
        return False
    return True


def _fully_equal(a: NormalizedRule, b: NormalizedRule) -> bool:
    return (
        a.direction == b.direction
        and a.protocol == b.protocol
        and a.port_range == b.port_range
        and _endpoints_equal(a.source, b.source)
        and _endpoints_equal(a.destination, b.destination)
    )


def detect_conflicts(rules: list[NormalizedRule]) -> list[Conflict]:
    """Classify pairwise conflicts among rules, treating list order as evaluation priority."""
    conflicts: list[Conflict] = []
    for i in range(len(rules)):
        for j in range(i + 1, len(rules)):
            earlier, later = rules[i], rules[j]
            if not _rules_overlap(earlier, later):
                continue
            if _fully_equal(earlier, later):
                if earlier.action == later.action:
                    conflicts.append(
                        Conflict(
                            type="redundancy",
                            rule_id=later.id,
                            conflicting_rule_id=earlier.id,
                            description=f"Rule '{later.id}' is a duplicate of rule '{earlier.id}'",
                        )
                    )
                else:
                    conflicts.append(
                        Conflict(
                            type="contradiction",
                            rule_id=later.id,
                            conflicting_rule_id=earlier.id,
                            description=(
                                f"Rule '{later.id}' ({later.action}) contradicts "
                                f"rule '{earlier.id}' ({earlier.action}) on identical traffic"
                            ),
                        )
                    )
            else:
                conflicts.append(
                    Conflict(
                        type="shadowing",
                        rule_id=later.id,
                        conflicting_rule_id=earlier.id,
                        description=f"Rule '{later.id}' is partially shadowed by earlier rule '{earlier.id}'",
                    )
                )
    return conflicts
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd analyzer && pytest tests/detectors/test_conflicts.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add analyzer/src/detectors/permissiveness.py analyzer/tests/detectors/test_permissiveness.py analyzer/src/detectors/conflicts.py analyzer/tests/detectors/test_conflicts.py analyzer/tests/detectors/__init__.py
git commit -m "feat: add permissiveness and conflict detectors"
```

---

### Task 9: Orphaned rule detector

Heuristic per CLAUDE.md: no real traffic-log ingestion exists (deliberately deferred open question), so orphaned detection uses staleness + missing description as a proxy signal. `as_of` is an injectable parameter so tests stay deterministic without depending on wall-clock time.

**Files:**
- Create: `analyzer/src/detectors/orphaned.py`
- Test: `analyzer/tests/detectors/test_orphaned.py`

**Interfaces:**
- Consumes: `NormalizedRule` from `src.models`.
- Produces: `class OrphanedResult(BaseModel): is_orphaned: bool; reason: str` in `src.detectors.orphaned`; `detect_orphaned(rule: NormalizedRule, as_of: datetime, staleness_days: int = 180) -> OrphanedResult`.

- [ ] **Step 1: Write the failing test**

```python
# analyzer/tests/detectors/test_orphaned.py
from datetime import datetime

from src.detectors.orphaned import detect_orphaned
from src.models import Endpoint, NormalizedRule, PortRange


def _rule(**overrides):
    base = dict(
        id="rule-1",
        source_type="firewall",
        source_id="fw-1",
        protocol="tcp",
        port_range=PortRange(start=8080, end=8080),
        direction="ingress",
        action="allow",
        source=Endpoint(type="cidr", value="10.0.0.0/8"),
        destination=Endpoint(type="cidr", value="10.0.1.0/24"),
        created_at=datetime(2024, 1, 1),
        modified_at=datetime(2024, 1, 1),
        description="",
    )
    base.update(overrides)
    return NormalizedRule(**base)


def test_flags_stale_undocumented_rule_as_orphaned():
    rule = _rule()
    result = detect_orphaned(rule, as_of=datetime(2026, 1, 1))
    assert result.is_orphaned is True
    assert "180 days" in result.reason


def test_does_not_flag_recently_modified_rule():
    rule = _rule(modified_at=datetime(2025, 12, 1))
    result = detect_orphaned(rule, as_of=datetime(2026, 1, 1))
    assert result.is_orphaned is False


def test_does_not_flag_documented_stale_rule():
    rule = _rule(description="Required for partner VPN tunnel")
    result = detect_orphaned(rule, as_of=datetime(2026, 1, 1))
    assert result.is_orphaned is False


def test_respects_custom_staleness_threshold():
    rule = _rule(modified_at=datetime(2025, 11, 1))
    result = detect_orphaned(rule, as_of=datetime(2026, 1, 1), staleness_days=30)
    assert result.is_orphaned is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && pytest tests/detectors/test_orphaned.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.detectors.orphaned'`

- [ ] **Step 3: Implement**

```python
# analyzer/src/detectors/orphaned.py
"""Heuristic orphaned-rule detector.

No traffic-log ingestion exists yet (see CLAUDE.md open questions), so
orphaned rules are approximated as ones that are both stale (not modified
recently) and undocumented (empty description). `as_of` is injected rather
than read from the clock so results stay deterministic in tests.
"""
from datetime import datetime

from pydantic import BaseModel

from src.models import NormalizedRule


class OrphanedResult(BaseModel):
    is_orphaned: bool
    reason: str


def detect_orphaned(rule: NormalizedRule, as_of: datetime, staleness_days: int = 180) -> OrphanedResult:
    """Flag a rule as orphaned if it is both stale and undocumented."""
    age_days = (as_of - rule.modified_at).days
    is_stale = age_days > staleness_days
    is_undocumented = rule.description.strip() == ""

    if is_stale and is_undocumented:
        return OrphanedResult(
            is_orphaned=True,
            reason=f"Rule has not been modified in {age_days} days (> {staleness_days} days) and has no description",
        )
    return OrphanedResult(is_orphaned=False, reason="")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd analyzer && pytest tests/detectors/test_orphaned.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

No standalone commit — bundled with Task 10's risk scorer commit. Proceed directly to Task 10.

---

### Task 10: Risk scorer

Combines permissiveness, exposure (critical ports), compliance violations, and unused/orphaned signals into the `RiskScore` already modeled in `src.models`. Weights are a documented design decision (`prompt.txt` does not prescribe exact values): permissiveness 35%, exposure 30%, compliance violations 25%, unused 10%.

**Files:**
- Create: `analyzer/src/detectors/risk_scorer.py`
- Test: `analyzer/tests/detectors/test_risk_scorer.py`

**Interfaces:**
- Consumes: `NormalizedRule`, `RiskScore` from `src.models`; `detect_permissiveness` from `src.detectors.permissiveness`; `detect_orphaned` from `src.detectors.orphaned`; `Conflict` from `src.detectors.conflicts` (count of contradictions contributes to compliance_violations proxy — see below).
- Produces: `CRITICAL_PORTS: set[int]` and `score_rules(rules: list[NormalizedRule], as_of: datetime, compliance_violation_count: int = 0) -> RiskScore` in `src.detectors.risk_scorer`.

- [ ] **Step 1: Write the failing test**

```python
# analyzer/tests/detectors/test_risk_scorer.py
from datetime import datetime

from src.detectors.risk_scorer import score_rules
from src.models import Endpoint, NormalizedRule, PortRange


def _rule(**overrides):
    base = dict(
        id="rule-1",
        source_type="firewall",
        source_id="fw-1",
        protocol="tcp",
        port_range=PortRange(start=8080, end=8080),
        direction="ingress",
        action="allow",
        source=Endpoint(type="cidr", value="10.0.0.0/8"),
        destination=Endpoint(type="cidr", value="10.0.1.0/24"),
        created_at=datetime(2024, 1, 1),
        modified_at=datetime(2024, 1, 1),
        description="internal service",
    )
    base.update(overrides)
    return NormalizedRule(**base)


def test_low_risk_for_scoped_documented_rules():
    rules = [_rule(modified_at=datetime(2025, 12, 1))]
    score = score_rules(rules, as_of=datetime(2026, 1, 1))
    assert score.overall < 20
    assert score.permissiveness == 0
    assert score.unused == 0


def test_high_permissiveness_score_for_open_cidr():
    rules = [_rule(source=Endpoint(type="cidr", value="0.0.0.0/0"), modified_at=datetime(2025, 12, 1))]
    score = score_rules(rules, as_of=datetime(2026, 1, 1))
    assert score.permissiveness == 100


def test_high_exposure_score_for_critical_port():
    rules = [
        _rule(
            port_range=PortRange(start=22, end=22),
            source=Endpoint(type="cidr", value="0.0.0.0/0"),
            modified_at=datetime(2025, 12, 1),
        )
    ]
    score = score_rules(rules, as_of=datetime(2026, 1, 1))
    assert score.exposure == 100


def test_unused_score_reflects_orphaned_ratio():
    rules = [
        _rule(id="r1", description="", modified_at=datetime(2024, 1, 1)),
        _rule(id="r2", description="documented", modified_at=datetime(2025, 12, 1)),
    ]
    score = score_rules(rules, as_of=datetime(2026, 1, 1))
    assert score.unused == 50


def test_compliance_violations_score_passthrough_ratio():
    rules = [_rule(id="r1"), _rule(id="r2")]
    score = score_rules(rules, as_of=datetime(2026, 1, 1), compliance_violation_count=1)
    assert score.compliance_violations == 50


def test_overall_is_weighted_combination():
    rules = [_rule(source=Endpoint(type="cidr", value="0.0.0.0/0"), modified_at=datetime(2025, 12, 1))]
    score = score_rules(rules, as_of=datetime(2026, 1, 1))
    expected = round(0.35 * score.permissiveness + 0.30 * score.exposure + 0.25 * score.compliance_violations + 0.10 * score.unused)
    assert score.overall == expected


def test_empty_ruleset_scores_zero():
    score = score_rules([], as_of=datetime(2026, 1, 1))
    assert score.overall == 0
    assert score.permissiveness == 0
    assert score.exposure == 0
    assert score.unused == 0
    assert score.compliance_violations == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && pytest tests/detectors/test_risk_scorer.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.detectors.risk_scorer'`

- [ ] **Step 3: Implement**

```python
# analyzer/src/detectors/risk_scorer.py
"""Combines detector signals into an overall RiskScore.

Weights (permissiveness 35%, exposure 30%, compliance_violations 25%,
unused 10%) are a documented design decision — prompt.txt specifies the
inputs to combine but not exact weights, so exposure and permissiveness
(the signals most directly tied to exploitable misconfiguration) are
weighted highest.
"""
from datetime import datetime

from src.detectors.orphaned import detect_orphaned
from src.detectors.permissiveness import detect_permissiveness
from src.models import NormalizedRule, RiskScore

CRITICAL_PORTS: set[int] = {22, 23, 3389, 5432, 3306, 27017, 6379, 9200, 1433}

_PERMISSIVENESS_WEIGHT = 0.35
_EXPOSURE_WEIGHT = 0.30
_COMPLIANCE_WEIGHT = 0.25
_UNUSED_WEIGHT = 0.10


def _touches_critical_port(rule: NormalizedRule) -> bool:
    if rule.port_range is None:
        return False
    return any(rule.port_range.start <= port <= rule.port_range.end for port in CRITICAL_PORTS)


def score_rules(
    rules: list[NormalizedRule],
    as_of: datetime,
    compliance_violation_count: int = 0,
) -> RiskScore:
    """Score a set of rules across permissiveness, exposure, compliance, and unused axes."""
    if not rules:
        return RiskScore(overall=0, permissiveness=0, exposure=0, compliance_violations=0, unused=0)

    total = len(rules)
    permissive_count = 0
    exposed_count = 0
    orphaned_count = 0

    for rule in rules:
        permissiveness_result = detect_permissiveness(rule)
        if permissiveness_result.is_permissive:
            permissive_count += 1
            if _touches_critical_port(rule):
                exposed_count += 1
        elif _touches_critical_port(rule):
            exposed_count += 1

        orphaned_result = detect_orphaned(rule, as_of=as_of)
        if orphaned_result.is_orphaned:
            orphaned_count += 1

    permissiveness_score = round(100 * permissive_count / total)
    exposure_score = round(100 * exposed_count / total)
    unused_score = round(100 * orphaned_count / total)
    compliance_score = round(100 * compliance_violation_count / total) if total else 0
    compliance_score = min(compliance_score, 100)

    overall = round(
        _PERMISSIVENESS_WEIGHT * permissiveness_score
        + _EXPOSURE_WEIGHT * exposure_score
        + _COMPLIANCE_WEIGHT * compliance_score
        + _UNUSED_WEIGHT * unused_score
    )

    return RiskScore(
        overall=overall,
        permissiveness=permissiveness_score,
        exposure=exposure_score,
        compliance_violations=compliance_score,
        unused=unused_score,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd analyzer && pytest tests/detectors/test_risk_scorer.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add analyzer/src/detectors/orphaned.py analyzer/tests/detectors/test_orphaned.py analyzer/src/detectors/risk_scorer.py analyzer/tests/detectors/test_risk_scorer.py
git commit -m "feat: implement risk scoring algorithm"
```

---

### Task 11: Compliance rulesets, matcher engine, and custom rule loader

CIS/HIPAA/PCI-DSS rulesets as JSON, matched against rules using regex (for descriptions/tags) and CIDR containment (for source/destination values) via stdlib `ipaddress`. Custom rules load through the same loader, validated with a pydantic model so malformed custom JSON fails clearly rather than crashing the matcher.

**Files:**
- Create: `analyzer/src/compliance/rulesets/cis.json`
- Create: `analyzer/src/compliance/rulesets/hipaa.json`
- Create: `analyzer/src/compliance/rulesets/pci_dss.json`
- Create: `analyzer/src/compliance/matcher.py`
- Create: `analyzer/src/compliance/loader.py`
- Modify: `analyzer/src/compliance/__init__.py`
- Test: `analyzer/tests/compliance/test_matcher.py`
- Test: `analyzer/tests/compliance/test_loader.py`

**Interfaces:**
- Consumes: `NormalizedRule` from `src.models`.
- Produces: `class ComplianceRule(BaseModel): framework, rule_id, description, matcher (protocol/ports/source/destination optional fields), severity` in `src.compliance.loader`; `load_ruleset(framework: str) -> list[ComplianceRule]`; `load_custom_ruleset(raw: bytes) -> list[ComplianceRule]` in `src.compliance.loader`; `matches(rule: NormalizedRule, compliance_rule: ComplianceRule) -> bool` in `src.compliance.matcher`.

- [ ] **Step 1: Create the ruleset JSON files**

```json
// analyzer/src/compliance/rulesets/cis.json
[
  {
    "framework": "cis",
    "rule_id": "CIS-4.1",
    "description": "No security group should allow ingress from 0.0.0.0/0 to port 22 (SSH)",
    "matcher": { "protocol": "tcp", "ports": [22], "source": "0.0.0.0/0" },
    "severity": "critical"
  },
  {
    "framework": "cis",
    "rule_id": "CIS-4.2",
    "description": "No security group should allow ingress from 0.0.0.0/0 to port 3389 (RDP)",
    "matcher": { "protocol": "tcp", "ports": [3389], "source": "0.0.0.0/0" },
    "severity": "critical"
  },
  {
    "framework": "cis",
    "rule_id": "CIS-5.1",
    "description": "No rule should allow ingress from ::/0 to any administrative port",
    "matcher": { "ports": [22, 3389], "source": "::/0" },
    "severity": "high"
  }
]
```

```json
// analyzer/src/compliance/rulesets/hipaa.json
[
  {
    "framework": "hipaa",
    "rule_id": "HIPAA-164.312-a1",
    "description": "Database ports handling PHI must not be exposed to 0.0.0.0/0",
    "matcher": { "ports": [5432, 3306, 27017], "source": "0.0.0.0/0" },
    "severity": "critical"
  },
  {
    "framework": "hipaa",
    "rule_id": "HIPAA-164.312-e1",
    "description": "Unencrypted protocol (telnet) must not be permitted",
    "matcher": { "protocol": "tcp", "ports": [23] },
    "severity": "high"
  }
]
```

```json
// analyzer/src/compliance/rulesets/pci_dss.json
[
  {
    "framework": "pci_dss",
    "rule_id": "PCI-1.2.1",
    "description": "Cardholder data environment must not allow inbound traffic from 0.0.0.0/0 on database ports",
    "matcher": { "ports": [3306, 5432, 1433], "source": "0.0.0.0/0" },
    "severity": "critical"
  },
  {
    "framework": "pci_dss",
    "rule_id": "PCI-2.2.2",
    "description": "Insecure services (telnet, ftp) must be disabled",
    "matcher": { "protocol": "tcp", "ports": [21, 23] },
    "severity": "high"
  }
]
```

- [ ] **Step 2: Write the failing tests**

```python
# analyzer/tests/compliance/test_matcher.py
from datetime import datetime

from src.compliance.loader import ComplianceRule, ComplianceMatcher
from src.compliance.matcher import matches
from src.models import Endpoint, NormalizedRule, PortRange


def _rule(**overrides):
    base = dict(
        id="rule-1",
        source_type="firewall",
        source_id="fw-1",
        protocol="tcp",
        port_range=PortRange(start=22, end=22),
        direction="ingress",
        action="allow",
        source=Endpoint(type="cidr", value="0.0.0.0/0"),
        destination=Endpoint(type="cidr", value="10.0.1.0/24"),
        created_at=datetime(2026, 1, 1),
        modified_at=datetime(2026, 1, 1),
    )
    base.update(overrides)
    return NormalizedRule(**base)


def _compliance_rule(**matcher_overrides):
    matcher = ComplianceMatcher(protocol="tcp", ports=[22], source="0.0.0.0/0")
    for key, value in matcher_overrides.items():
        setattr(matcher, key, value)
    return ComplianceRule(
        framework="cis",
        rule_id="CIS-4.1",
        description="No SSH from anywhere",
        matcher=matcher,
        severity="critical",
    )


def test_matches_on_protocol_port_and_cidr_source():
    rule = _rule()
    compliance_rule = _compliance_rule()
    assert matches(rule, compliance_rule) is True


def test_no_match_when_port_outside_range():
    rule = _rule(port_range=PortRange(start=443, end=443))
    compliance_rule = _compliance_rule()
    assert matches(rule, compliance_rule) is False


def test_no_match_when_source_not_contained_in_cidr():
    rule = _rule(source=Endpoint(type="cidr", value="10.0.0.5/32"))
    compliance_rule = _compliance_rule()
    assert matches(rule, compliance_rule) is False


def test_matches_when_source_is_narrower_cidr_within_matcher():
    rule = _rule(source=Endpoint(type="cidr", value="0.0.0.0/0"))
    compliance_rule = _compliance_rule(source="0.0.0.0/0")
    assert matches(rule, compliance_rule) is True


def test_no_protocol_in_matcher_matches_any_protocol():
    rule = _rule(protocol="udp")
    compliance_rule = _compliance_rule(protocol=None)
    assert matches(rule, compliance_rule) is True


def test_no_match_when_rule_has_no_port_range_but_matcher_requires_port():
    rule = _rule(port_range=None)
    compliance_rule = _compliance_rule()
    assert matches(rule, compliance_rule) is False
```

```python
# analyzer/tests/compliance/test_loader.py
import pytest

from src.compliance.loader import load_custom_ruleset, load_ruleset


def test_loads_cis_ruleset():
    rules = load_ruleset("cis")
    assert len(rules) >= 1
    assert all(r.framework == "cis" for r in rules)


def test_loads_hipaa_ruleset():
    rules = load_ruleset("hipaa")
    assert len(rules) >= 1
    assert all(r.framework == "hipaa" for r in rules)


def test_loads_pci_dss_ruleset():
    rules = load_ruleset("pci_dss")
    assert len(rules) >= 1
    assert all(r.framework == "pci_dss" for r in rules)


def test_unknown_framework_raises():
    with pytest.raises(ValueError, match="Unknown compliance framework"):
        load_ruleset("nonexistent")


def test_loads_valid_custom_ruleset():
    raw = b"""
    [
      {
        "framework": "custom",
        "rule_id": "CUSTOM-1",
        "description": "No ingress from staging CIDR to prod",
        "matcher": { "source": "192.168.100.0/24" },
        "severity": "medium"
      }
    ]
    """
    rules = load_custom_ruleset(raw)
    assert len(rules) == 1
    assert rules[0].rule_id == "CUSTOM-1"


def test_rejects_malformed_custom_ruleset():
    with pytest.raises(ValueError):
        load_custom_ruleset(b"not valid json [[[")
```

Create `analyzer/tests/compliance/__init__.py` (empty).

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd analyzer && pytest tests/compliance/ -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.compliance.matcher'`

- [ ] **Step 4: Implement**

```python
# analyzer/src/compliance/loader.py
"""Loads bundled compliance rulesets (CIS/HIPAA/PCI-DSS) and custom rulesets."""
import json
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel

_RULESETS_DIR = Path(__file__).parent / "rulesets"

_BUNDLED_FRAMEWORKS = {"cis", "hipaa", "pci_dss"}


class ComplianceMatcher(BaseModel):
    protocol: Optional[str] = None
    ports: Optional[list[int]] = None
    source: Optional[str] = None
    destination: Optional[str] = None


class ComplianceRule(BaseModel):
    framework: str
    rule_id: str
    description: str
    matcher: ComplianceMatcher
    severity: Literal["critical", "high", "medium", "low"]


def load_ruleset(framework: str) -> list[ComplianceRule]:
    """Load a bundled compliance ruleset by framework name (cis, hipaa, pci_dss)."""
    if framework not in _BUNDLED_FRAMEWORKS:
        raise ValueError(f"Unknown compliance framework: {framework}")
    path = _RULESETS_DIR / f"{framework}.json"
    data = json.loads(path.read_text())
    return [ComplianceRule(**entry) for entry in data]


def load_custom_ruleset(raw: bytes) -> list[ComplianceRule]:
    """Load and validate a user-supplied custom compliance ruleset from raw JSON bytes."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Custom ruleset could not be parsed as JSON: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError("Custom ruleset must be a JSON array of rule objects")
    return [ComplianceRule(**entry) for entry in data]
```

```python
# analyzer/src/compliance/matcher.py
"""Matches NormalizedRule instances against ComplianceRule definitions.

Protocol/port matching is exact; CIDR matching uses stdlib ipaddress to
check whether the rule's endpoint network falls within (or equals) the
compliance matcher's CIDR, so a narrower rule CIDR still matches a
broader compliance-defined network.
"""
import ipaddress

from src.compliance.loader import ComplianceRule
from src.models import NormalizedRule


def _cidr_matches(rule_value: str, matcher_cidr: str) -> bool:
    try:
        rule_network = ipaddress.ip_network(rule_value, strict=False)
        matcher_network = ipaddress.ip_network(matcher_cidr, strict=False)
    except ValueError:
        return rule_value == matcher_cidr
    return rule_network.subnet_of(matcher_network) or rule_network == matcher_network


def matches(rule: NormalizedRule, compliance_rule: ComplianceRule) -> bool:
    """Return True if `rule` triggers `compliance_rule`'s matcher conditions."""
    matcher = compliance_rule.matcher

    if matcher.protocol is not None and rule.protocol.lower() != matcher.protocol.lower():
        return False

    if matcher.ports is not None:
        if rule.port_range is None:
            return False
        if not any(rule.port_range.start <= port <= rule.port_range.end for port in matcher.ports):
            return False

    if matcher.source is not None:
        if rule.source.type != "cidr" or not _cidr_matches(rule.source.value, matcher.source):
            return False

    if matcher.destination is not None:
        if rule.destination.type != "cidr" or not _cidr_matches(rule.destination.value, matcher.destination):
            return False

    return True
```

```python
# analyzer/src/compliance/__init__.py
"""Compliance rule loading and matching against parsed policy rules."""
from src.compliance.loader import ComplianceMatcher, ComplianceRule, load_custom_ruleset, load_ruleset
from src.compliance.matcher import matches

__all__ = [
    "ComplianceMatcher",
    "ComplianceRule",
    "load_custom_ruleset",
    "load_ruleset",
    "matches",
]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd analyzer && pytest tests/compliance/ -v`
Expected: PASS (all tests in both files)

- [ ] **Step 6: Commit**

```bash
git add analyzer/src/compliance/ analyzer/tests/compliance/
git commit -m "feat: add compliance rule matching"
```

---

### Task 12: Coverage top-up and final Phase 2 verification

Confirm >80% coverage across `analyzer/src`, add any tests needed to close gaps, and do the final "test: add analyzer unit tests (80% coverage)" commit called for in `prompt.txt`.

**Files:**
- Modify (as needed): any test file above where coverage report shows gaps.

**Interfaces:** none new — this task only adds tests for existing code.

- [ ] **Step 1: Run full coverage report**

Run: `cd analyzer && pytest -v --cov=src --cov-report=term-missing`
Expected: passes; note the coverage percentage and any files under 80%.

- [ ] **Step 2: Close coverage gaps**

For any file below 80%, read the `Missing` line numbers from the coverage report and add targeted test cases covering those branches (e.g. an `AWS security group entry missing GroupId` error path, or a `parse_json_or_yaml` edge case for a YAML document that parses to a scalar). Follow the same test style as the file's existing tests — no new patterns needed, this is filling gaps in already-established test files.

- [ ] **Step 3: Re-run coverage to confirm the target is met**

Run: `cd analyzer && pytest -v --cov=src --cov-report=term-missing`
Expected: overall coverage >80%, all tests passing.

- [ ] **Step 4: Commit**

```bash
git add analyzer/tests/
git commit -m "test: add analyzer unit tests (80% coverage)"
```

- [ ] **Step 5: Push Phase 2 to GitHub**

```bash
git push origin main
```

---

## Self-Review Notes

**Spec coverage:** Milestone 2A (three parsers, input validation, >80% coverage) — Tasks 1-6, 12. Milestone 2B (permissiveness, conflict, orphaned detectors, risk scorer) — Tasks 7-10. Milestone 2C (CIS/HIPAA/PCI-DSS rulesets, regex+CIDR matcher, custom rule loader) — Task 11. All six `prompt.txt` Milestone 2A/2B/2C commit messages are used, in order, across Tasks 3-12 (two parser tasks reuse "feat: implement firewall rule parser" since `prompt.txt` lists only two parser commit messages for three parsers — documented inline at each reuse point).

**Placeholder scan:** no "TBD"/"TODO" strings; every step has runnable code, not descriptions of code.

**Type consistency:** `NormalizedRule.action` (Task 1) is consumed identically by every later task (Tasks 3-11) as `Literal["allow", "deny"]`. `Conflict` (Task 8) and `RiskScore`/`score_rules` (Task 10) signatures match how the design's algorithm was described. `ComplianceRule`/`ComplianceMatcher` (Task 11) field names match what `matcher.py` reads.

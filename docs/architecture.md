# Architecture

## Project Overview

A security-focused tool for analyzing network policies, firewall rules, and IAM configurations to detect misconfigurations, overly permissive rules, conflicts, and compliance violations. Provides a policy recommendation engine and interactive visualization of network traffic flows.

**Primary Use Case:** Security teams analyzing multi-cloud infrastructure, audit compliance checks, and infrastructure-as-code reviews.

---

## System Layers

```
┌─────────────────────────────────────────────────────────┐
│                   React Frontend (UI)                   │
│  - Policy upload & parsing                              │
│  - Interactive network diagram visualization            │
│  - Risk matrix & compliance dashboard                   │
│  - Rule detail inspector & diff viewer                  │
└──────────────────────────────┬──────────────────────────┘
                               │ HTTP/WebSocket
┌──────────────────────────────▼──────────────────────────┐
│         Node.js/Express API Layer (TypeScript)          │
│  - File upload & validation                             │
│  - Analysis orchestration                               │
│  - Report generation                                    │
│  - Real-time analysis progress (WebSocket)              │
└──────────────────────────────┬──────────────────────────┘
                               │ HTTP
┌──────────────────────────────▼──────────────────────────┐
│      Python Analysis Engine (FastAPI)                   │
│  - Rule parsing (firewall, security groups, IAM)        │
│  - Permissiveness detection                             │
│  - Conflict detection                                   │
│  - Compliance rule matching                              │
│  - Recommendations generation                           │
└──────────────────────────────┬──────────────────────────┘
                               │
┌──────────────────────────────▴──────────────────────────┐
│              MongoDB (Data Storage)                      │
│  - Policy configurations (versioned)                    │
│  - Analysis results & reports                           │
│  - User accounts & sessions                              │
│  - Compliance rule definitions                           │
└─────────────────────────────────────────────────────────┘
```

## Microservice Decomposition

- **api** (Node.js/Express) - HTTP endpoints, auth, file handling
- **analyzer** (Python/FastAPI) - Rule analysis, compliance checking, recommendations
- **frontend** (React/TypeScript) - UI, visualization, dashboards
- **mongo** (MongoDB) - Persistent storage

---

## Tech Stack Details

### Backend (API Gateway)
- **Language:** TypeScript
- **Framework:** Express.js
- **Database ORM:** Mongoose (MongoDB)
- **WebSocket:** Socket.io (for real-time analysis progress, planned)

### Analysis Engine
- **Language:** Python 3.9+
- **Framework:** FastAPI (async, fast, auto-docs)
- **Key Libraries:**
  - `pyyaml` - YAML parsing
  - `jsonschema` - JSON schema validation
  - `networkx` - Graph algorithms for rule relationships
  - `pydantic` - Data validation
  - `pytest` - Testing

### Frontend
- **Framework:** React 18
- **Language:** TypeScript
- **Styling:** Tailwind CSS
- **Visualization:** Cytoscape.js (network graphs) + Recharts (charts/stats), planned
- **Testing:** Vitest + React Testing Library

### Infrastructure
- **Containerization:** Docker + Docker Compose
- **Database:** MongoDB 6+
- **Package Managers:** npm (Node.js), pip (Python)

---

## Core Concepts & Design Decisions

### 1. Rule Abstraction Model

All rule types (AWS Security Groups, firewall rules, IAM policies) are normalized into a common internal model, shared verbatim between the API (TypeScript) and analyzer (pydantic):

```typescript
interface NormalizedRule {
  id: string;
  source_type: 'security_group' | 'firewall' | 'iam_policy';
  source_id: string;  // SG ID, firewall name, etc.

  // Traffic layer
  protocol: string;   // tcp, udp, icmp, any
  port_range: PortRange | null;
  direction: 'ingress' | 'egress';

  // Endpoints
  source: Endpoint;   // CIDR, IP, security group, principal
  destination: Endpoint;

  // Metadata
  created_at: Date;
  modified_at: Date;
  description: string;
  tags: Record<string, string>;
}

interface Endpoint {
  type: 'cidr' | 'ip' | 'security_group' | 'principal';
  value: string;  // 0.0.0.0/0, 10.0.0.0/8, sg-123, arn:aws:iam::...
}

interface PortRange {
  start: number;
  end: number;
}
```

**Rationale:** Abstracts vendor-specific formats. Same analysis logic works on AWS, GCP, Kubernetes, on-prem firewalls.

### 2. Severity Scoring System

Rules are scored on risk, with adjustable weights:

```typescript
interface RiskScore {
  overall: number;               // 0-100
  permissiveness: number;        // 0-100, e.g. 0.0.0.0/0, ::/0
  exposure: number;              // 0-100, critical ports (22, 3389, 5432)
  compliance_violations: number; // 0-100
  unused: number;                // 0-100, rules with no matching traffic
}
```

**Rationale:** Allows sorting findings by business relevance, not just technical risk.

### 3. Conflict Detection Strategy

Three types of conflicts:

- **Shadowing:** Rule A makes Rule B impossible to reach (ordering issue)
- **Redundancy:** Rules A and B are functionally identical
- **Contradictions:** Rules A (allow 22) and B (deny 22) on same resource

**Implementation:** Build a conflict graph; run topological sort to detect cycles/chains.

### 4. Compliance Framework

Rules are matched against:
- CIS Benchmarks (e.g., "No security group allows ingress from 0.0.0.0/0 to port 22")
- HIPAA/PCI-DSS checklists
- Custom user-defined rules (via JSON)

**Rationale:** Different industries need different compliance checks; make it pluggable.

### 5. Recommendation Engine

Heuristic-based: rules suggest specific fixes (e.g. if a rule is "allow ::/0 to port 22", recommend restricting the CIDR).

---

## Database Schema (MongoDB)

### Collections

**policies**
```javascript
{
  _id: ObjectId,
  user_id: string,
  name: string,
  description: string,
  source_type: 'aws' | 'firewall' | 'iam',
  raw_content: string,  // original JSON/YAML
  normalized_rules: [ NormalizedRule ],
  created_at: Date,
  updated_at: Date,
  tags: [ string ],
}
```

**analyses**
```javascript
{
  _id: ObjectId,
  policy_id: ObjectId,
  risk_score: RiskScore,
  findings: [
    {
      type: 'overly_permissive' | 'conflict' | 'orphaned' | 'compliance_violation',
      severity: 'critical' | 'high' | 'medium' | 'low',
      rule_id: string,
      description: string,
      recommendation: string,
    }
  ],
  generated_at: Date,
}
```

**compliance_rules**
```javascript
{
  _id: ObjectId,
  framework: 'cis' | 'hipaa' | 'pci_dss' | 'custom',
  rule_id: string,
  description: string,
  matcher: {
    protocol?: string,
    ports?: [ number ],
    source?: string,  // regex or CIDR
    destination?: string,
  },
  severity: 'critical' | 'high' | 'medium' | 'low',
}
```

**users**
```javascript
{
  _id: ObjectId,
  email: string,
  password_hash: string,
  name: string,
  created_at: Date,
  updated_at: Date,
}
```

---

## Key Development Notes

### Permissiveness Detection
- `0.0.0.0/0` (any IPv4) and `::/0` (any IPv6)
- `any-protocol` or protocol unspecified
- Port range `0-65535`
- Principals: `*` or `Principal: *`

### CIDR/IP Handling
- Use `ipaddress` (Python) for CIDR math (overlaps, containment)
- Handle IPv4 and IPv6 uniformly

### Large Policy Sets
- Use MongoDB aggregation pipeline for complex queries
- Cache analysis results (add `hash` field to detect changes)
- Consider a background job queue for large-scale async analysis

### Security Considerations
- **Input validation:** Validate all uploaded files (size, format)
- **Output sanitization:** Don't leak sensitive data (IPs, ARNs) in error messages
- **Auth:** Multi-user support with JWT; users can only see their own policies
- **CORS:** Locked down to known origins

---

## Testing Strategy

- **Python (analyzer):** pytest for parsers, detectors, scoring — target 85%+ coverage
- **Node.js (api):** Jest for route handlers and middleware — target 75%+ coverage
- **React (frontend):** Vitest + React Testing Library — target 60%+ coverage, focused on behavior not snapshots
- **Integration:** API ↔ analyzer HTTP contract, database CRUD, file upload → parse → analyze pipeline
- **End-to-end:** Upload → analyze → view results → export report

---

## Deployment (Docker)

`docker-compose.yml` defines:
- `api` - Node.js/Express service
- `analyzer` - Python/FastAPI service
- `frontend` - React (built static files served via nginx)
- `mongo` - MongoDB

**Env vars:**
- `MONGODB_URI`
- `API_PORT`, `ANALYZER_PORT`, `FRONTEND_PORT`
- `JWT_SECRET`
- `MAX_FILE_SIZE`
- `ANALYSIS_TIMEOUT`

Inside Docker Compose, `MONGODB_URI` must point at the `mongo` service name (`mongodb://mongo:27017/analyzer`), not `localhost` — the API container overrides this in `docker-compose.yml`.

---

## Success Criteria

- Correctly identify 95%+ of manually-flagged rule issues
- Handle policies with 1000+ rules without degradation
- API response time < 2s for a typical policy
- Comprehensive test coverage (>70%)
- Clear, actionable recommendations for each finding
- Easy onboarding for new compliance rule types

---

## Future Enhancements

1. **Traffic baseline:** Accept network flow logs to detect unused rules
2. **Change tracking:** Diff policies between versions and flag new violations
3. **Auto-remediation:** Generate Terraform/CloudFormation to fix violations
4. **Scheduled scanning:** Auto-scan policies on a schedule and alert on changes
5. **Multi-cloud:** Extend beyond AWS to GCP, Azure

---

## External Resources

- [OWASP Network Security Best Practices](https://owasp.org)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security)
- [FastAPI Docs](https://fastapi.tiangolo.com)
- [React Best Practices](https://react.dev)

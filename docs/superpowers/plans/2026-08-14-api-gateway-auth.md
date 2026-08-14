# API Gateway & Auth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Phase 3 (`prompt.txt` Milestones 3A/3B/3C) — expose the Phase 2 analysis engine over HTTP, then build the Express API's file upload, analysis orchestration with real-time WebSocket progress, PDF report generation, and JWT authentication with per-user resource isolation.

**Architecture:** The Python analyzer gains two HTTP endpoints (`POST /parse`, `POST /analyze`) that wrap the pure-function modules built in Phase 2 — no new business logic, just an HTTP boundary. The Express API becomes the orchestrator: it authenticates requests, stores `Policy`/`Analysis` documents in MongoDB, and calls the analyzer over HTTP rather than reimplementing any analysis logic. Real-time progress is modeled as a small number of discrete stage events (not fine-grained streaming, since the analyzer call itself is a single synchronous HTTP request) emitted over Socket.io to a room keyed by policy ID.

**Tech Stack:** Express 4 + TypeScript (existing), Mongoose 8 (existing), `jsonwebtoken` (existing), `bcryptjs` (new — pure JS, no native build step), `multer` (new — multipart file upload), `zod` (new — request validation), `socket.io` (new — WebSocket progress), `pdfkit` (new — PDF report generation), Node 18+ global `fetch`/`FormData`/`Blob` (no new HTTP client dependency needed) for calling the analyzer service, `mongodb-memory-server` + `socket.io-client` (new devDependencies — integration tests).

## Global Constraints

- No AI/Claude/LLM attribution anywhere in code, comments, or commit messages.
- Commit messages for Milestone 3A/3B/3C work must be the exact strings from `prompt.txt`, used in this order: "feat: add file upload endpoint and validation", "feat: implement analysis API and orchestration", "feat: add JWT authentication", "feat: implement report generation", "test: add API integration tests". The analyzer HTTP wiring (Task 1) is prerequisite infrastructure not named in `prompt.txt`'s list, so it gets its own descriptive Conventional Commit message, matching the precedent set by Phase 2's Task 1.
- Field names in every JSON payload crossing the API↔analyzer boundary must match `analyzer/src/models.py` / `api/src/models/NormalizedRule.ts` exactly (already guaranteed by Phase 2 — no translation layer).
- `Policy.source_type` (`'aws' | 'firewall' | 'iam'`) is a coarser categorization than `NormalizedRule.source_type` (`'security_group' | 'firewall' | 'iam_policy'`); the upload route must map between them (`aws` → `security_group`, `iam` → `iam_policy`, `firewall` → `firewall`).
- Users may only see/modify their own `Policy`/`Analysis` documents — any cross-user access attempt returns 403, not 404 (confirms existence is intentionally not hidden, per `prompt.txt`'s testing checklist: "Attempt to access another user's policy (should 403)").
- Malformed/oversized uploads must return a 4xx JSON error, never an unhandled 500.
- Follow existing code style: typed Express handlers, `AuthenticatedRequest` for protected routes, module docstring/comment only where non-obvious.

---

## File Structure

```
analyzer/src/
  main.py                          (MODIFY — add /parse, /analyze endpoints)
  api_models.py                    (NEW — AnalyzeRequest/AnalyzeResponse pydantic models)
analyzer/tests/
  test_main.py                     (NEW — endpoint tests)

api/src/
  config/env.ts                    (MODIFY — add pythonAnalyzerUrl, nodeEnv)
  services/analyzerClient.ts       (NEW — HTTP client for the analyzer's /parse, /analyze)
  services/authService.ts          (NEW — hashPassword, verifyPassword, issueToken)
  services/reportService.ts        (NEW — PDF generation)
  websocket/server.ts              (NEW — Socket.io attach + emitProgress helper)
  routes/auth.ts                   (NEW — register/login/refresh)
  routes/policies.ts               (MODIFY — upload/list/get/delete/analyze)
  routes/analyses.ts               (MODIFY — get/report)
  routes/index.ts                  (MODIFY — mount authRouter)
  index.ts                         (MODIFY — attach Socket.io to the HTTP server)
api/tests/
  services/authService.test.ts     (NEW)
  routes/auth.test.ts              (NEW)
  routes/policies.test.ts          (NEW)
  routes/analyses.test.ts          (NEW)
  helpers/testDb.ts                (NEW — mongodb-memory-server setup/teardown)
  helpers/fixtures.ts              (NEW — shared fixture data)
```

---

### Task 1: Expose the analysis engine over HTTP

**Files:**
- Create: `analyzer/src/api_models.py`
- Modify: `analyzer/src/main.py`
- Test: `analyzer/tests/test_main.py`

**Interfaces:**
- Consumes: `parse_policy` from `src.parsers`; `detect_permissiveness`, `detect_conflicts`, `detect_orphaned`, `score_rules` from `src.detectors.*`; `load_ruleset`, `matches` from `src.compliance`; `ParserError` from `src.parsers.exceptions`.
- Produces: `POST /parse` (multipart: `source_type` form field + `file`) → `list[NormalizedRule]` JSON. `POST /analyze` (JSON body `AnalyzeRequest`) → `AnalyzeResponse` JSON.

- [ ] **Step 1: Write the failing test**

```python
# analyzer/tests/test_main.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && pytest tests/test_main.py -v`
Expected: FAIL — `404 Not Found` for both endpoints (they don't exist yet).

- [ ] **Step 3: Implement**

```python
# analyzer/src/api_models.py
"""Request/response models for the analyzer's HTTP API."""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from src.detectors.conflicts import Conflict
from src.models import Finding, NormalizedRule, RiskScore


class AnalyzeRequest(BaseModel):
    rules: list[NormalizedRule]
    compliance_frameworks: list[str] = []
    as_of: Optional[datetime] = None


class AnalyzeResponse(BaseModel):
    risk_score: RiskScore
    findings: list[Finding]
```

```python
# analyzer/src/main.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd analyzer && pytest tests/test_main.py -v`
Expected: PASS (7 tests)

Then run full analyzer suite with coverage: `cd analyzer && pytest -v --cov=src --cov-report=term-missing` — expect all tests still passing, coverage should remain high; if `main.py`/`api_models.py` show gaps, that's acceptable at this stage (this task's own tests already exercise the main paths).

- [ ] **Step 5: Commit**

```bash
git add analyzer/src/main.py analyzer/src/api_models.py analyzer/tests/test_main.py
git commit -m "feat: expose analysis engine via HTTP API"
```

---

### Task 2: Environment config and analyzer HTTP client

**Files:**
- Modify: `api/src/config/env.ts`
- Create: `api/src/services/analyzerClient.ts`
- Test: `api/tests/services/analyzerClient.test.ts`

**Interfaces:**
- Produces: `env.pythonAnalyzerUrl: string`, `env.nodeEnv: string`. `parsePolicyViaAnalyzer(raw: Buffer, sourceType: string, filename: string): Promise<NormalizedRule[]>` and `analyzeRulesViaAnalyzer(rules: NormalizedRule[], complianceFrameworks: string[]): Promise<{ risk_score: RiskScore; findings: Finding[] }>` in `api/src/services/analyzerClient.ts`.

- [ ] **Step 1: Write the failing test**

```typescript
// api/tests/services/analyzerClient.test.ts
import { analyzeRulesViaAnalyzer, parsePolicyViaAnalyzer } from '../../src/services/analyzerClient';

const originalFetch = global.fetch;

afterEach(() => {
  global.fetch = originalFetch;
  jest.restoreAllMocks();
});

describe('parsePolicyViaAnalyzer', () => {
  it('posts multipart form data and returns parsed rules', async () => {
    const mockRules = [{ id: 'r1', protocol: 'tcp' }];
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => mockRules,
    }) as unknown as typeof fetch;

    const result = await parsePolicyViaAnalyzer(Buffer.from('{}'), 'firewall', 'rules.json');

    expect(result).toEqual(mockRules);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/parse'),
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('throws with the analyzer error detail when the response is not ok', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 400,
      json: async () => ({ detail: 'Unsupported source_type: bogus' }),
    }) as unknown as typeof fetch;

    await expect(parsePolicyViaAnalyzer(Buffer.from('{}'), 'bogus', 'rules.json')).rejects.toThrow(
      'Unsupported source_type: bogus',
    );
  });
});

describe('analyzeRulesViaAnalyzer', () => {
  it('posts JSON and returns risk score and findings', async () => {
    const mockResponse = { risk_score: { overall: 10 }, findings: [] };
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => mockResponse,
    }) as unknown as typeof fetch;

    const result = await analyzeRulesViaAnalyzer([], ['cis']);

    expect(result).toEqual(mockResponse);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd api && npx jest tests/services/analyzerClient.test.ts`
Expected: FAIL — `Cannot find module '../../src/services/analyzerClient'`

- [ ] **Step 3: Implement**

```typescript
// api/src/config/env.ts (add fields to EnvConfig and the exported env object)
interface EnvConfig {
  apiPort: number;
  mongodbUri: string;
  jwtSecret: string;
  maxFileSize: number;
  analysisTimeout: number;
  frontendPort: number;
  pythonAnalyzerUrl: string;
  nodeEnv: string;
}
```

Add to the `env` object literal (after `frontendPort`):

```typescript
  pythonAnalyzerUrl: required('PYTHON_ANALYZER_URL', 'http://localhost:8000'),
  nodeEnv: required('NODE_ENV', 'development'),
```

```typescript
// api/src/services/analyzerClient.ts
import { NormalizedRule, RiskScore } from '../models/NormalizedRule';
import { Finding } from '../models/Analysis';
import { env } from '../config/env';

export interface AnalyzeResult {
  risk_score: RiskScore;
  findings: Finding[];
}

async function readErrorDetail(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: string };
    return body.detail ?? `Analyzer request failed with status ${response.status}`;
  } catch {
    return `Analyzer request failed with status ${response.status}`;
  }
}

export async function parsePolicyViaAnalyzer(
  raw: Buffer,
  sourceType: string,
  filename: string,
): Promise<NormalizedRule[]> {
  const form = new FormData();
  form.append('source_type', sourceType);
  form.append('file', new Blob([raw]), filename);

  const response = await fetch(`${env.pythonAnalyzerUrl}/parse`, {
    method: 'POST',
    body: form,
  });

  if (!response.ok) {
    throw new Error(await readErrorDetail(response));
  }

  return (await response.json()) as NormalizedRule[];
}

export async function analyzeRulesViaAnalyzer(
  rules: NormalizedRule[],
  complianceFrameworks: string[],
): Promise<AnalyzeResult> {
  const response = await fetch(`${env.pythonAnalyzerUrl}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rules, compliance_frameworks: complianceFrameworks }),
  });

  if (!response.ok) {
    throw new Error(await readErrorDetail(response));
  }

  return (await response.json()) as AnalyzeResult;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd api && npx jest tests/services/analyzerClient.test.ts`
Expected: PASS (3 tests)

Then verify the build: `cd api && npm run build` — expect PASS, no type errors.

- [ ] **Step 5: Commit**

```bash
git add api/src/config/env.ts api/src/services/analyzerClient.ts api/tests/services/analyzerClient.test.ts
git commit -m "feat: add analyzer HTTP client and config"
```

---

### Task 3: JWT authentication (register, login, refresh)

**Files:**
- Create: `api/src/services/authService.ts`
- Create: `api/src/routes/auth.ts`
- Modify: `api/src/routes/index.ts`
- Test: `api/tests/services/authService.test.ts`
- Test: `api/tests/routes/auth.test.ts`
- Create: `api/tests/helpers/testDb.ts`

**Interfaces:**
- Consumes: `User` model from `../models/User`; `env` from `../config/env`.
- Produces: `hashPassword(password: string): Promise<string>`, `verifyPassword(password: string, hash: string): Promise<boolean>`, `issueToken(userId: string): string` in `api/src/services/authService.ts`. `authRouter` mounted at `/api/auth` with `POST /register`, `POST /login`, `POST /refresh`.

- [ ] **Step 1: Add the shared in-memory MongoDB test helper**

```typescript
// api/tests/helpers/testDb.ts
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';

let mongoServer: MongoMemoryServer;

export async function connectTestDb(): Promise<void> {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());
}

export async function clearTestDb(): Promise<void> {
  const collections = mongoose.connection.collections;
  for (const key of Object.keys(collections)) {
    await collections[key].deleteMany({});
  }
}

export async function disconnectTestDb(): Promise<void> {
  await mongoose.disconnect();
  await mongoServer.stop();
}
```

- [ ] **Step 2: Write the failing tests**

```typescript
// api/tests/services/authService.test.ts
import { hashPassword, issueToken, verifyPassword } from '../../src/services/authService';
import jwt from 'jsonwebtoken';
import { env } from '../../src/config/env';

describe('authService', () => {
  it('hashes a password and verifies it correctly', async () => {
    const hash = await hashPassword('correct horse battery staple');
    expect(hash).not.toEqual('correct horse battery staple');
    expect(await verifyPassword('correct horse battery staple', hash)).toBe(true);
    expect(await verifyPassword('wrong password', hash)).toBe(false);
  });

  it('issues a JWT containing the userId', () => {
    const token = issueToken('user-123');
    const payload = jwt.verify(token, env.jwtSecret) as { userId: string };
    expect(payload.userId).toBe('user-123');
  });
});
```

```typescript
// api/tests/routes/auth.test.ts
import request from 'supertest';
import { createApp } from '../../src/app';
import { User } from '../../src/models/User';
import { clearTestDb, connectTestDb, disconnectTestDb } from '../helpers/testDb';

beforeAll(async () => {
  await connectTestDb();
});

afterEach(async () => {
  await clearTestDb();
});

afterAll(async () => {
  await disconnectTestDb();
});

describe('POST /api/auth/register', () => {
  it('creates a user and returns a token', async () => {
    const app = createApp();
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'test@example.com', password: 'password123', name: 'Test User' });

    expect(res.status).toBe(201);
    expect(res.body.token).toBeDefined();
    const stored = await User.findOne({ email: 'test@example.com' });
    expect(stored).not.toBeNull();
  });

  it('rejects duplicate email registration', async () => {
    const app = createApp();
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'dup@example.com', password: 'password123' });
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'dup@example.com', password: 'password123' });

    expect(res.status).toBe(409);
  });

  it('rejects invalid input', async () => {
    const app = createApp();
    const res = await request(app).post('/api/auth/register').send({ email: 'not-an-email' });

    expect(res.status).toBe(400);
  });
});

describe('POST /api/auth/login', () => {
  it('returns a token for correct credentials', async () => {
    const app = createApp();
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'login@example.com', password: 'password123' });

    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'login@example.com', password: 'password123' });

    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
  });

  it('rejects incorrect password', async () => {
    const app = createApp();
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'login2@example.com', password: 'password123' });

    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'login2@example.com', password: 'wrong' });

    expect(res.status).toBe(401);
  });
});

describe('POST /api/auth/refresh', () => {
  it('issues a new token for a valid existing token', async () => {
    const app = createApp();
    const registerRes = await request(app)
      .post('/api/auth/register')
      .send({ email: 'refresh@example.com', password: 'password123' });

    const res = await request(app)
      .post('/api/auth/refresh')
      .set('Authorization', `Bearer ${registerRes.body.token}`);

    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
  });

  it('rejects a missing token', async () => {
    const app = createApp();
    const res = await request(app).post('/api/auth/refresh');

    expect(res.status).toBe(401);
  });
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd api && npx jest tests/services/authService.test.ts tests/routes/auth.test.ts`
Expected: FAIL — `Cannot find module '../../src/services/authService'` and `authRouter` not mounted.

- [ ] **Step 4: Implement**

```typescript
// api/src/services/authService.ts
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { env } from '../config/env';

const SALT_ROUNDS = 10;
const TOKEN_TTL = '24h';

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function issueToken(userId: string): string {
  return jwt.sign({ userId }, env.jwtSecret, { expiresIn: TOKEN_TTL });
}
```

```typescript
// api/src/routes/auth.ts
import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { User } from '../models/User';
import { hashPassword, issueToken, verifyPassword } from '../services/authService';
import { authenticate, AuthenticatedRequest } from '../middleware/auth';

export const authRouter = Router();

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

authRouter.post('/register', async (req: Request, res: Response): Promise<void> => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid registration data', details: parsed.error.flatten() });
    return;
  }

  const { email, password, name } = parsed.data;
  const existing = await User.findOne({ email });
  if (existing) {
    res.status(409).json({ error: 'Email already registered' });
    return;
  }

  const password_hash = await hashPassword(password);
  const user = await User.create({ email, password_hash, name });
  res.status(201).json({ token: issueToken(user.id) });
});

authRouter.post('/login', async (req: Request, res: Response): Promise<void> => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid login data' });
    return;
  }

  const { email, password } = parsed.data;
  const user = await User.findOne({ email }).select('+password_hash');
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    res.status(401).json({ error: 'Invalid email or password' });
    return;
  }

  res.status(200).json({ token: issueToken(user.id) });
});

authRouter.post('/refresh', authenticate, (req: AuthenticatedRequest, res: Response): void => {
  res.status(200).json({ token: issueToken(req.userId as string) });
});
```

```typescript
// api/src/routes/index.ts
import { Router } from 'express';
import { authRouter } from './auth';
import { policiesRouter } from './policies';
import { analysesRouter } from './analyses';
import { complianceRulesRouter } from './complianceRules';

export const apiRouter = Router();

apiRouter.use('/auth', authRouter);
apiRouter.use('/policies', policiesRouter);
apiRouter.use('/analyses', analysesRouter);
apiRouter.use('/compliance-rules', complianceRulesRouter);
```

- [ ] **Step 5: Install new dependencies**

```bash
cd api && npm install bcryptjs zod && npm install -D @types/bcryptjs mongodb-memory-server
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd api && npx jest tests/services/authService.test.ts tests/routes/auth.test.ts`
Expected: PASS (7 tests)

- [ ] **Step 7: Commit**

```bash
git add api/src/services/authService.ts api/src/routes/auth.ts api/src/routes/index.ts api/tests/services/authService.test.ts api/tests/routes/auth.test.ts api/tests/helpers/testDb.ts api/package.json api/package-lock.json
git commit -m "feat: add JWT authentication"
```

---

### Task 4: File upload endpoint and policy CRUD with ownership checks

**Files:**
- Modify: `api/src/routes/policies.ts`
- Test: `api/tests/routes/policies.test.ts`
- Create: `api/tests/helpers/fixtures.ts`

**Interfaces:**
- Consumes: `parsePolicyViaAnalyzer` from `../services/analyzerClient`; `authenticate`, `AuthenticatedRequest` from `../middleware/auth`; `Policy` from `../models/Policy`; `env` from `../config/env`.
- Produces: `POST /api/policies/upload`, `GET /api/policies`, `GET /api/policies/:id`, `DELETE /api/policies/:id`, all mounted under `authenticate`.

- [ ] **Step 1: Add shared test fixtures**

```typescript
// api/tests/helpers/fixtures.ts
export const VALID_FIREWALL_POLICY = Buffer.from(
  JSON.stringify({
    rules: [
      {
        name: 'allow-ssh',
        protocol: 'tcp',
        port: 22,
        direction: 'ingress',
        action: 'allow',
        source: { type: 'cidr', value: '0.0.0.0/0' },
        destination: { type: 'cidr', value: '10.0.0.0/8' },
      },
    ],
  }),
);
```

- [ ] **Step 2: Write the failing tests**

```typescript
// api/tests/routes/policies.test.ts
import request from 'supertest';
import { createApp } from '../../src/app';
import { clearTestDb, connectTestDb, disconnectTestDb } from '../helpers/testDb';
import { VALID_FIREWALL_POLICY } from '../helpers/fixtures';
import * as analyzerClient from '../../src/services/analyzerClient';

beforeAll(async () => {
  await connectTestDb();
});

afterEach(async () => {
  await clearTestDb();
  jest.restoreAllMocks();
});

afterAll(async () => {
  await disconnectTestDb();
});

async function registerAndLogin(app: ReturnType<typeof createApp>, email: string): Promise<string> {
  const res = await request(app).post('/api/auth/register').send({ email, password: 'password123' });
  return res.body.token as string;
}

describe('POST /api/policies/upload', () => {
  it('rejects requests without a token', async () => {
    const app = createApp();
    const res = await request(app).post('/api/policies/upload').field('name', 'test').field('source_type', 'firewall');
    expect(res.status).toBe(401);
  });

  it('parses and stores an uploaded policy', async () => {
    const app = createApp();
    const token = await registerAndLogin(app, 'upload@example.com');
    jest.spyOn(analyzerClient, 'parsePolicyViaAnalyzer').mockResolvedValue([
      {
        id: 'r1',
        source_type: 'firewall',
        source_id: 'fw-1',
        protocol: 'tcp',
        port_range: { start: 22, end: 22 },
        direction: 'ingress',
        action: 'allow',
        source: { type: 'cidr', value: '0.0.0.0/0' },
        destination: { type: 'cidr', value: '10.0.0.0/8' },
        created_at: new Date(),
        modified_at: new Date(),
        description: '',
        tags: {},
      },
    ]);

    const res = await request(app)
      .post('/api/policies/upload')
      .set('Authorization', `Bearer ${token}`)
      .field('name', 'my-firewall')
      .field('source_type', 'firewall')
      .attach('file', VALID_FIREWALL_POLICY, 'rules.json');

    expect(res.status).toBe(201);
    expect(res.body.normalized_rules).toHaveLength(1);
  });

  it('rejects a file over the configured size limit', async () => {
    const app = createApp();
    const token = await registerAndLogin(app, 'toobig@example.com');
    const big = Buffer.alloc(11 * 1024 * 1024, 1);

    const res = await request(app)
      .post('/api/policies/upload')
      .set('Authorization', `Bearer ${token}`)
      .field('name', 'big-policy')
      .field('source_type', 'firewall')
      .attach('file', big, 'rules.json');

    expect(res.status).toBe(413);
  });
});

describe('GET /api/policies and ownership isolation', () => {
  it('lists only the requesting user\'s policies', async () => {
    const app = createApp();
    const tokenA = await registerAndLogin(app, 'userA@example.com');
    const tokenB = await registerAndLogin(app, 'userB@example.com');
    jest.spyOn(analyzerClient, 'parsePolicyViaAnalyzer').mockResolvedValue([]);

    await request(app)
      .post('/api/policies/upload')
      .set('Authorization', `Bearer ${tokenA}`)
      .field('name', 'a-policy')
      .field('source_type', 'firewall')
      .attach('file', VALID_FIREWALL_POLICY, 'rules.json');

    const res = await request(app).get('/api/policies').set('Authorization', `Bearer ${tokenB}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });

  it('returns 403 when fetching another user\'s policy', async () => {
    const app = createApp();
    const tokenA = await registerAndLogin(app, 'ownerA@example.com');
    const tokenB = await registerAndLogin(app, 'ownerB@example.com');
    jest.spyOn(analyzerClient, 'parsePolicyViaAnalyzer').mockResolvedValue([]);

    const uploadRes = await request(app)
      .post('/api/policies/upload')
      .set('Authorization', `Bearer ${tokenA}`)
      .field('name', 'private-policy')
      .field('source_type', 'firewall')
      .attach('file', VALID_FIREWALL_POLICY, 'rules.json');

    const res = await request(app)
      .get(`/api/policies/${uploadRes.body._id}`)
      .set('Authorization', `Bearer ${tokenB}`);

    expect(res.status).toBe(403);
  });

  it('deletes an owned policy', async () => {
    const app = createApp();
    const token = await registerAndLogin(app, 'deleter@example.com');
    jest.spyOn(analyzerClient, 'parsePolicyViaAnalyzer').mockResolvedValue([]);

    const uploadRes = await request(app)
      .post('/api/policies/upload')
      .set('Authorization', `Bearer ${token}`)
      .field('name', 'to-delete')
      .field('source_type', 'firewall')
      .attach('file', VALID_FIREWALL_POLICY, 'rules.json');

    const res = await request(app)
      .delete(`/api/policies/${uploadRes.body._id}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(204);
  });
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd api && npx jest tests/routes/policies.test.ts`
Expected: FAIL — current `policiesRouter` only has a stub `GET /` returning 501.

- [ ] **Step 4: Implement**

```typescript
// api/src/routes/policies.ts
import { Router, Response } from 'express';
import multer from 'multer';
import { z } from 'zod';
import { authenticate, AuthenticatedRequest } from '../middleware/auth';
import { env } from '../config/env';
import { Policy } from '../models/Policy';
import { parsePolicyViaAnalyzer } from '../services/analyzerClient';

export const policiesRouter = Router();

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: env.maxFileSize } });

const SOURCE_TYPE_MAP: Record<string, string> = {
  aws: 'security_group',
  firewall: 'firewall',
  iam: 'iam_policy',
};

const uploadMetadataSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional().default(''),
  source_type: z.enum(['aws', 'firewall', 'iam']),
});

policiesRouter.use(authenticate);

policiesRouter.post(
  '/upload',
  (req, res, next) => {
    upload.single('file')(req, res, (err) => {
      if (err && err.code === 'LIMIT_FILE_SIZE') {
        res.status(413).json({ error: 'File exceeds maximum allowed size' });
        return;
      }
      if (err) {
        res.status(400).json({ error: 'File upload failed' });
        return;
      }
      next();
    });
  },
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const parsed = uploadMetadataSchema.safeParse(req.body);
    if (!parsed.success || !req.file) {
      res.status(400).json({ error: 'Invalid upload: name, source_type, and file are required' });
      return;
    }

    const { name, description, source_type } = parsed.data;
    const analyzerSourceType = SOURCE_TYPE_MAP[source_type];

    try {
      const normalized_rules = await parsePolicyViaAnalyzer(req.file.buffer, analyzerSourceType, req.file.originalname);
      const policy = await Policy.create({
        user_id: req.userId,
        name,
        description,
        source_type,
        raw_content: req.file.buffer.toString('utf-8'),
        normalized_rules,
        tags: [],
      });
      res.status(201).json(policy);
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  },
);

policiesRouter.get('/', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const policies = await Policy.find({ user_id: req.userId }).sort({ created_at: -1 });
  res.status(200).json(policies);
});

policiesRouter.get('/:id', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const policy = await Policy.findById(req.params.id);
  if (!policy) {
    res.status(404).json({ error: 'Policy not found' });
    return;
  }
  if (policy.user_id !== req.userId) {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }
  res.status(200).json(policy);
});

policiesRouter.delete('/:id', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const policy = await Policy.findById(req.params.id);
  if (!policy) {
    res.status(404).json({ error: 'Policy not found' });
    return;
  }
  if (policy.user_id !== req.userId) {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }
  await policy.deleteOne();
  res.status(204).send();
});
```

- [ ] **Step 5: Install new dependency**

```bash
cd api && npm install multer && npm install -D @types/multer
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd api && npx jest tests/routes/policies.test.ts`
Expected: PASS (7 tests)

- [ ] **Step 7: Commit**

```bash
git add api/src/routes/policies.ts api/tests/routes/policies.test.ts api/tests/helpers/fixtures.ts api/package.json api/package-lock.json
git commit -m "feat: add file upload endpoint and validation"
```

---

### Task 5: Analysis orchestration with WebSocket progress

**Files:**
- Create: `api/src/websocket/server.ts`
- Modify: `api/src/index.ts`
- Modify: `api/src/routes/policies.ts` (add `POST /:id/analyze`)
- Modify: `api/src/routes/analyses.ts` (add `GET /:id`)
- Test: `api/tests/routes/policies.test.ts` (append analyze tests)
- Test: `api/tests/routes/analyses.test.ts`

**Interfaces:**
- Consumes: `analyzeRulesViaAnalyzer` from `../services/analyzerClient`; `Analysis` model; `Policy` model.
- Produces: `attachSocketIO(httpServer: http.Server): SocketIOServer` and `emitProgress(policyId: string, stage: string, percent: number): void` in `api/src/websocket/server.ts`. `POST /api/policies/:id/analyze` → creates and returns an `Analysis` document. `GET /api/analyses/:id` → fetches one, enforcing ownership through its parent `Policy`.

- [ ] **Step 1: Write the failing tests**

```typescript
// api/src/websocket/server.ts (test-relevant behavior verified via socket.io-client below)
```

```typescript
// api/tests/routes/analyses.test.ts
import http from 'http';
import { AddressInfo } from 'net';
import { io as ioClient, Socket } from 'socket.io-client';
import request from 'supertest';
import { createApp } from '../../src/app';
import { attachSocketIO } from '../../src/websocket/server';
import { clearTestDb, connectTestDb, disconnectTestDb } from '../helpers/testDb';
import { VALID_FIREWALL_POLICY } from '../helpers/fixtures';
import * as analyzerClient from '../../src/services/analyzerClient';

let server: http.Server;
let baseUrl: string;

beforeAll(async () => {
  await connectTestDb();
  const app = createApp();
  server = http.createServer(app);
  attachSocketIO(server);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const { port } = server.address() as AddressInfo;
  baseUrl = `http://localhost:${port}`;
});

afterEach(async () => {
  await clearTestDb();
  jest.restoreAllMocks();
});

afterAll(async () => {
  await disconnectTestDb();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

async function registerAndUpload(): Promise<{ token: string; policyId: string }> {
  const app = createApp();
  const registerRes = await request(app).post('/api/auth/register').send({ email: 'analyze@example.com', password: 'password123' });
  const token = registerRes.body.token as string;

  jest.spyOn(analyzerClient, 'parsePolicyViaAnalyzer').mockResolvedValue([]);
  const uploadRes = await request(app)
    .post('/api/policies/upload')
    .set('Authorization', `Bearer ${token}`)
    .field('name', 'analyze-target')
    .field('source_type', 'firewall')
    .attach('file', VALID_FIREWALL_POLICY, 'rules.json');

  return { token, policyId: uploadRes.body._id as string };
}

describe('POST /api/policies/:id/analyze', () => {
  it('triggers analysis and stores results', async () => {
    const app = createApp();
    const { token, policyId } = await registerAndUpload();

    jest.spyOn(analyzerClient, 'analyzeRulesViaAnalyzer').mockResolvedValue({
      risk_score: { overall: 42, permissiveness: 10, exposure: 20, compliance_violations: 5, unused: 0 },
      findings: [],
    });

    const res = await request(app)
      .post(`/api/policies/${policyId}/analyze`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(201);
    expect(res.body.risk_score.overall).toBe(42);
  });

  it('emits progress events over the WebSocket', async () => {
    const { token, policyId } = await registerAndUpload();

    jest.spyOn(analyzerClient, 'analyzeRulesViaAnalyzer').mockResolvedValue({
      risk_score: { overall: 0, permissiveness: 0, exposure: 0, compliance_violations: 0, unused: 0 },
      findings: [],
    });

    const client: Socket = ioClient(`${baseUrl}/ws/analyze`, { transports: ['websocket'] });
    const events: Array<{ stage: string; percent: number }> = [];

    await new Promise<void>((resolve) => {
      client.on('connect', () => {
        client.emit('join', policyId);
        resolve();
      });
    });

    client.on('progress', (payload: { stage: string; percent: number }) => {
      events.push(payload);
    });

    const analyzeApp = createApp();
    await request(analyzeApp)
      .post(`/api/policies/${policyId}/analyze`)
      .set('Authorization', `Bearer ${token}`);

    await new Promise((resolve) => setTimeout(resolve, 200));

    expect(events.some((e) => e.percent === 100)).toBe(true);
    client.close();
  });
});

describe('GET /api/analyses/:id', () => {
  it('returns the stored analysis for the owning user', async () => {
    const app = createApp();
    const { token, policyId } = await registerAndUpload();

    jest.spyOn(analyzerClient, 'analyzeRulesViaAnalyzer').mockResolvedValue({
      risk_score: { overall: 5, permissiveness: 0, exposure: 0, compliance_violations: 0, unused: 0 },
      findings: [],
    });

    const analyzeRes = await request(app)
      .post(`/api/policies/${policyId}/analyze`)
      .set('Authorization', `Bearer ${token}`);

    const res = await request(app)
      .get(`/api/analyses/${analyzeRes.body._id}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.risk_score.overall).toBe(5);
  });

  it('returns 403 for another user\'s analysis', async () => {
    const app = createApp();
    const { token, policyId } = await registerAndUpload();
    const otherRes = await request(app).post('/api/auth/register').send({ email: 'other@example.com', password: 'password123' });

    jest.spyOn(analyzerClient, 'analyzeRulesViaAnalyzer').mockResolvedValue({
      risk_score: { overall: 5, permissiveness: 0, exposure: 0, compliance_violations: 0, unused: 0 },
      findings: [],
    });

    const analyzeRes = await request(app)
      .post(`/api/policies/${policyId}/analyze`)
      .set('Authorization', `Bearer ${token}`);

    const res = await request(app)
      .get(`/api/analyses/${analyzeRes.body._id}`)
      .set('Authorization', `Bearer ${otherRes.body.token}`);

    expect(res.status).toBe(403);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd api && npx jest tests/routes/analyses.test.ts`
Expected: FAIL — `attachSocketIO` module doesn't exist; `POST /:id/analyze` and `GET /api/analyses/:id` aren't implemented.

- [ ] **Step 3: Implement**

```typescript
// api/src/websocket/server.ts
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import { env } from '../config/env';

let io: SocketIOServer | undefined;

export function attachSocketIO(server: http.Server): SocketIOServer {
  io = new SocketIOServer(server, {
    path: '/ws/analyze',
    cors: { origin: `http://localhost:${env.frontendPort}` },
  });

  io.on('connection', (socket) => {
    socket.on('join', (policyId: string) => {
      socket.join(`analyze:${policyId}`);
    });
  });

  return io;
}

export function emitProgress(policyId: string, stage: string, percent: number): void {
  io?.to(`analyze:${policyId}`).emit('progress', { stage, percent });
}
```

```typescript
// api/src/index.ts
import http from 'http';
import { createApp } from './app';
import { connectDb } from './config/db';
import { env } from './config/env';
import { attachSocketIO } from './websocket/server';

async function main(): Promise<void> {
  await connectDb();

  const app = createApp();
  const server = http.createServer(app);
  attachSocketIO(server);

  server.listen(env.apiPort, () => {
    console.log(`API listening on port ${env.apiPort}`);
  });
}

main().catch((err) => {
  console.error('Failed to start API server', err);
  process.exit(1);
});
```

Add to `api/src/routes/policies.ts` (after the `DELETE /:id` handler):

```typescript
import { Analysis } from '../models/Analysis';
import { analyzeRulesViaAnalyzer } from '../services/analyzerClient';
import { emitProgress } from '../websocket/server';

policiesRouter.post('/:id/analyze', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const policy = await Policy.findById(req.params.id);
  if (!policy) {
    res.status(404).json({ error: 'Policy not found' });
    return;
  }
  if (policy.user_id !== req.userId) {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }

  const complianceFrameworks = ['cis', 'hipaa', 'pci_dss'];

  try {
    emitProgress(policy.id, 'sending_to_analyzer', 25);
    const { risk_score, findings } = await analyzeRulesViaAnalyzer(policy.normalized_rules, complianceFrameworks);
    emitProgress(policy.id, 'scoring_complete', 75);

    const analysis = await Analysis.create({
      policy_id: policy._id,
      risk_score,
      findings,
    });
    emitProgress(policy.id, 'complete', 100);

    res.status(201).json(analysis);
  } catch (err) {
    emitProgress(policy.id, 'failed', 100);
    res.status(502).json({ error: (err as Error).message });
  }
});
```

Note: the `import` statements above must be merged into `policies.ts`'s existing import block, not duplicated — when editing, add `Analysis`, `analyzeRulesViaAnalyzer`, and `emitProgress` to the top of the file alongside the existing imports.

```typescript
// api/src/routes/analyses.ts
import { Router, Response } from 'express';
import { authenticate, AuthenticatedRequest } from '../middleware/auth';
import { Analysis } from '../models/Analysis';
import { Policy } from '../models/Policy';

export const analysesRouter = Router();

analysesRouter.use(authenticate);

analysesRouter.get('/:id', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const analysis = await Analysis.findById(req.params.id);
  if (!analysis) {
    res.status(404).json({ error: 'Analysis not found' });
    return;
  }
  const policy = await Policy.findById(analysis.policy_id);
  if (!policy || policy.user_id !== req.userId) {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }
  res.status(200).json(analysis);
});
```

- [ ] **Step 4: Install new dependencies**

```bash
cd api && npm install socket.io && npm install -D socket.io-client
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd api && npx jest tests/routes/analyses.test.ts tests/routes/policies.test.ts`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add api/src/websocket/server.ts api/src/index.ts api/src/routes/policies.ts api/src/routes/analyses.ts api/tests/routes/analyses.test.ts api/package.json api/package-lock.json
git commit -m "feat: implement analysis API and orchestration"
```

---

### Task 6: PDF report generation

**Files:**
- Create: `api/src/services/reportService.ts`
- Modify: `api/src/routes/analyses.ts` (add `GET /:id/report`)
- Test: `api/tests/services/reportService.test.ts`
- Test: `api/tests/routes/analyses.test.ts` (append report test)

**Interfaces:**
- Consumes: `AnalysisDocument` from `../models/Analysis`; `PolicyDocument` from `../models/Policy`.
- Produces: `generateReportPdf(policy: PolicyDocument, analysis: AnalysisDocument): Promise<Buffer>` in `api/src/services/reportService.ts`. `GET /api/analyses/:id/report` streams `application/pdf`.

- [ ] **Step 1: Write the failing tests**

```typescript
// api/tests/services/reportService.test.ts
import { generateReportPdf } from '../../src/services/reportService';

describe('generateReportPdf', () => {
  it('produces a non-empty PDF buffer containing finding descriptions', async () => {
    const policy = { name: 'test-policy', source_type: 'firewall' } as never;
    const analysis = {
      risk_score: { overall: 55, permissiveness: 60, exposure: 40, compliance_violations: 30, unused: 10 },
      findings: [
        {
          type: 'overly_permissive',
          severity: 'high',
          rule_id: 'r1',
          description: 'Allows traffic from 0.0.0.0/0',
          recommendation: 'Restrict the source CIDR.',
        },
      ],
      generated_at: new Date('2026-01-01'),
    } as never;

    const buffer = await generateReportPdf(policy, analysis);

    expect(buffer.length).toBeGreaterThan(0);
    expect(buffer.subarray(0, 4).toString()).toBe('%PDF');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd api && npx jest tests/services/reportService.test.ts`
Expected: FAIL — `Cannot find module '../../src/services/reportService'`

- [ ] **Step 3: Implement**

```typescript
// api/src/services/reportService.ts
import PDFDocument from 'pdfkit';
import { AnalysisDocument } from '../models/Analysis';
import { PolicyDocument } from '../models/Policy';

export function generateReportPdf(policy: PolicyDocument, analysis: AnalysisDocument): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50 });
    const chunks: Buffer[] = [];

    doc.on('data', (chunk: Buffer) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    doc.fontSize(20).text(`Policy Analysis Report: ${policy.name}`, { underline: true });
    doc.moveDown();
    doc.fontSize(12).text(`Source type: ${policy.source_type}`);
    doc.text(`Generated: ${analysis.generated_at.toISOString()}`);
    doc.moveDown();

    doc.fontSize(16).text('Risk Score');
    doc.fontSize(12).text(`Overall: ${analysis.risk_score.overall}`);
    doc.text(`Permissiveness: ${analysis.risk_score.permissiveness}`);
    doc.text(`Exposure: ${analysis.risk_score.exposure}`);
    doc.text(`Compliance violations: ${analysis.risk_score.compliance_violations}`);
    doc.text(`Unused: ${analysis.risk_score.unused}`);
    doc.moveDown();

    doc.fontSize(16).text('Findings');
    if (analysis.findings.length === 0) {
      doc.fontSize(12).text('No findings.');
    }
    for (const finding of analysis.findings) {
      doc.moveDown(0.5);
      doc.fontSize(13).text(`[${finding.severity.toUpperCase()}] ${finding.type} — rule ${finding.rule_id}`);
      doc.fontSize(11).text(finding.description);
      doc.fontSize(11).text(`Recommendation: ${finding.recommendation}`);
    }

    doc.end();
  });
}
```

Add to `api/src/routes/analyses.ts`:

```typescript
import { generateReportPdf } from '../services/reportService';

analysesRouter.get('/:id/report', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const analysis = await Analysis.findById(req.params.id);
  if (!analysis) {
    res.status(404).json({ error: 'Analysis not found' });
    return;
  }
  const policy = await Policy.findById(analysis.policy_id);
  if (!policy || policy.user_id !== req.userId) {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }

  const pdf = await generateReportPdf(policy, analysis);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="analysis-${analysis.id}.pdf"`);
  res.status(200).send(pdf);
});
```

- [ ] **Step 4: Install new dependency**

```bash
cd api && npm install pdfkit && npm install -D @types/pdfkit
```

- [ ] **Step 5: Write the report route test**

Append to `api/tests/routes/analyses.test.ts`:

```typescript
describe('GET /api/analyses/:id/report', () => {
  it('streams a PDF containing the analysis findings', async () => {
    const app = createApp();
    const { token, policyId } = await registerAndUpload();

    jest.spyOn(analyzerClient, 'analyzeRulesViaAnalyzer').mockResolvedValue({
      risk_score: { overall: 10, permissiveness: 0, exposure: 0, compliance_violations: 0, unused: 0 },
      findings: [
        {
          type: 'overly_permissive',
          severity: 'high',
          rule_id: 'r1',
          description: 'Allows traffic from 0.0.0.0/0',
          recommendation: 'Restrict the source CIDR.',
        },
      ],
    });

    const analyzeRes = await request(app)
      .post(`/api/policies/${policyId}/analyze`)
      .set('Authorization', `Bearer ${token}`);

    const res = await request(app)
      .get(`/api/analyses/${analyzeRes.body._id}/report`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('application/pdf');
    expect(res.body.subarray(0, 4).toString()).toBe('%PDF');
  });
});
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd api && npx jest tests/services/reportService.test.ts tests/routes/analyses.test.ts`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add api/src/services/reportService.ts api/src/routes/analyses.ts api/tests/services/reportService.test.ts api/tests/routes/analyses.test.ts api/package.json api/package-lock.json
git commit -m "feat: implement report generation"
```

---

### Task 7: Integration test coverage top-up

**Files:**
- Modify (as needed): any test file above where the coverage report shows gaps.

**Interfaces:** none new — this task only adds tests for existing code.

- [ ] **Step 1: Run the full API test suite with coverage**

Run: `cd api && npx jest --coverage`
Expected: all tests pass; note the coverage percentage and any files under 75% (the API's Testing Strategy target per CLAUDE.md).

- [ ] **Step 2: Close coverage gaps**

For any route or service below 75%, add targeted tests for the missing branches (e.g. `errorHandler`'s headers-already-sent branch, the `/parse` non-ok-response error path in `analyzerClient`, `GET /api/policies/:id` for a nonexistent ID returning 404). Follow the same test style as the existing files in `api/tests/` — no new patterns needed.

- [ ] **Step 3: Re-run coverage to confirm the target is met**

Run: `cd api && npx jest --coverage`
Expected: overall coverage >75%, all tests passing.

- [ ] **Step 4: Verify the full stack still type-checks and builds**

Run: `cd api && npm run build`
Expected: PASS, no type errors.

- [ ] **Step 5: Commit**

```bash
git add api/tests/
git commit -m "test: add API integration tests"
```

- [ ] **Step 6: Push Phase 3 to GitHub**

```bash
git push origin main
```

---

## Self-Review Notes

**Spec coverage:** Milestone 3A (upload, list, get, delete, validation) — Task 4. Milestone 3B (analyze trigger, WebSocket progress, get analysis, PDF report) — Tasks 5-6. Milestone 3C (JWT register/login/refresh, middleware, user isolation) — Task 3, enforced throughout Tasks 4-6. The analyzer HTTP wiring (Task 1) and the analyzer client/env config (Task 2) are prerequisite infrastructure, following the same precedent as Phase 2's Task 1. All five `prompt.txt` Milestone 3A/3B/3C commit messages are used, in order, across Tasks 3-7.

**Placeholder scan:** no "TBD"/"TODO" strings; every step has runnable code, not descriptions of code.

**Type consistency:** `AnalyzeRequest`/`AnalyzeResponse` (Task 1) field names match what `analyzerClient.ts` (Task 2) sends/expects. `parsePolicyViaAnalyzer`/`analyzeRulesViaAnalyzer` signatures (Task 2) match their call sites in `policies.ts` (Tasks 4-5). `attachSocketIO`/`emitProgress` (Task 5) are consumed identically in `index.ts` and `policies.ts`. `generateReportPdf` (Task 6) signature matches its call site in `analyses.ts`.

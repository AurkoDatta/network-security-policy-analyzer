# Polish, Testing & Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Phase 5 (`prompt.txt` Milestones 5A/5B/5C/5D) — close out the project with performance/E2E-journey tests, real caching, real documentation, CI, and optimized Docker images. Phases 2-4 already meet or exceed every per-phase coverage target (analyzer 100%, API 96%, frontend 97%, all above their 85%/75%/60% goals), commit hygiene and AI-attribution rules have been followed throughout, and `LICENSE` (MIT) already exists — so Milestone 5A's remaining work is E2E/performance tests specifically (not raw coverage percentage), and Milestone 5D's remaining work is just CI, since attribution/commit-style/license are already satisfied.

**Architecture:** No new services or schemas beyond what Phases 2-4 built. This phase adds: an in-memory TTL cache for repeated analysis of unchanged policies plus a `content_hash` field/index on `Policy`; structured JSON error logging; multi-step "critical journey" integration tests that chain several real HTTP calls end-to-end against the real in-memory MongoDB (analyzer calls are mocked, matching every existing API test — the analyzer's own HTTP contract is already independently verified by `analyzer/tests/test_main.py`'s real FastAPI `TestClient` calls, so this is a deliberate, reliable substitute for spawning the analyzer as a live subprocess, which would add CI flakiness for no additional confidence); a synthetic 1000+-rule performance test in the analyzer; real `docs/api.md`, `docs/user-guide.md`, `CONTRIBUTING.md`, and corrected `README.md` claims; a GitHub Actions workflow running all three test suites; and a multi-stage `analyzer/Dockerfile` plus `.dockerignore` files for `api/` and `analyzer/` (matching the `frontend/` one that already exists).

## Global Constraints

- No AI/Claude/LLM attribution anywhere in code, comments, commit messages, or docs.
- Commit messages must be the exact strings from `prompt.txt`'s Milestone 5A-5D list, used in this order: "perf: optimize MongoDB queries and caching", "test: add comprehensive test suite (85% coverage)", "docs: add API documentation and user guide", "ci: add GitHub Actions workflow for testing", "chore: optimize Docker images for production". (Structured error logging has no dedicated `prompt.txt` message — it lands in the perf commit alongside caching, since both are runtime-quality improvements to the same request path, following the precedent of folding prerequisite work into the nearest fitting commit from Phases 2-4.)
- Never change an already-tested, already-pushed HTTP response contract. The analysis cache must not alter `POST /:id/analyze`'s existing `201` response or any existing test's expected body shape — it only skips the redundant analyzer HTTP call, not the `Analysis` document creation.
- Cache keys must be scoped per-policy (`policy_id` + content hash), not by content alone — a content-only key would let two different tests' (or two different users', in production) byte-identical-but-unrelated policies collide on the same cache entry, silently returning one test's/user's mocked result to another. Export a `clearAnalysisCache()` test-only helper and call it in `afterEach` of any test file that exercises the analyze endpoint more than once, for full isolation regardless.
- Docker changes are reviewed for correctness but cannot be build-verified in this environment (no `docker` binary available here) — note this explicitly rather than silently claiming "verified."

---

## File Structure

```
api/src/
  models/Policy.ts                 (MODIFY — add content_hash field + index)
  routes/policies.ts                (MODIFY — compute content_hash, use analysis cache)
  services/analysisCache.ts         (NEW — TTL cache keyed by policy_id + content hash)
  middleware/errorHandler.ts        (MODIFY — structured JSON error logs)
api/tests/
  services/analysisCache.test.ts    (NEW)
  middleware/errorHandler.test.ts   (MODIFY — assert structured log shape)
  routes/policies.test.ts           (MODIFY — assert analyzer called once across repeat analyze calls)
  e2e/criticalJourneys.test.ts      (NEW)

analyzer/src/compliance/loader.py   (MODIFY — cache load_ruleset with lru_cache)
analyzer/tests/compliance/test_loader.py (MODIFY — assert the file is only read once)
analyzer/tests/test_performance.py  (NEW)

docs/api.md                         (MODIFY — real endpoint reference)
docs/user-guide.md                  (MODIFY — real walkthrough)
CONTRIBUTING.md                     (NEW)
README.md                           (MODIFY — correct GCP/compliance-rules/WebSocket-path claims)

.github/workflows/test.yml          (NEW)

analyzer/Dockerfile                 (MODIFY — multi-stage build)
analyzer/.dockerignore              (NEW)
api/.dockerignore                   (NEW)
```

---

### Task 1: Analysis result caching, content hash, and structured error logging

**Files:**
- Modify: `api/src/models/Policy.ts`
- Create: `api/src/services/analysisCache.ts`
- Modify: `api/src/routes/policies.ts`
- Modify: `api/src/middleware/errorHandler.ts`
- Modify: `analyzer/src/compliance/loader.py`
- Test: `api/tests/services/analysisCache.test.ts`
- Test: `api/tests/routes/policies.test.ts` (append)
- Test: `api/tests/middleware/errorHandler.test.ts` (append)
- Test: `analyzer/tests/compliance/test_loader.py` (append)

**Interfaces:**
- Produces: `getCachedAnalysis(key: string): AnalyzeResult | undefined`, `setCachedAnalysis(key: string, result: AnalyzeResult): void`, `clearAnalysisCache(): void`, `buildCacheKey(policyId: string, contentHash: string, frameworks: string[]): string` in `api/src/services/analysisCache.ts`. `Policy.content_hash: string` field + index. `load_ruleset` in `analyzer/src/compliance/loader.py` becomes `functools.lru_cache`-wrapped.

- [ ] **Step 1: Write the failing analyzer test**

```python
# analyzer/tests/compliance/test_loader.py (append)
from unittest.mock import patch

from src.compliance.loader import load_ruleset


def test_load_ruleset_reads_the_file_only_once_across_repeated_calls():
    # lru_cache is process-wide, so any fake data cached here must be
    # cleared afterward or later tests in the same session (which expect
    # the real bundled ruleset) would see this test's stale fake entry.
    load_ruleset.cache_clear()
    try:
        with patch("pathlib.Path.read_text", wraps=None) as mock_read:
            mock_read.return_value = '[{"framework": "cis", "rule_id": "X", "description": "d", "matcher": {}, "severity": "low"}]'
            load_ruleset("cis")
            load_ruleset("cis")
            assert mock_read.call_count == 1
    finally:
        load_ruleset.cache_clear()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && pytest tests/compliance/test_loader.py::test_load_ruleset_reads_the_file_only_once_across_repeated_calls -v`
Expected: FAIL — `load_ruleset` has no `cache_clear` attribute (it isn't cached yet), so `read_text` is called twice.

- [ ] **Step 3: Implement the analyzer cache**

```python
# analyzer/src/compliance/loader.py — add the import and decorator
import functools
import json
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel
```

```python
@functools.lru_cache(maxsize=None)
def load_ruleset(framework: str) -> list[ComplianceRule]:
    """Load a bundled compliance ruleset by framework name (cis, hipaa, pci_dss).

    Bundled rulesets never change at runtime, so results are cached for the
    life of the process — repeated analyze calls for the same framework
    don't re-read and re-parse the ruleset JSON file each time.
    """
    if framework not in _BUNDLED_FRAMEWORKS:
        raise ValueError(f"Unknown compliance framework: {framework}")
    path = _RULESETS_DIR / f"{framework}.json"
    data = json.loads(path.read_text())
    return [ComplianceRule(**entry) for entry in data]
```

(Only the `import functools` line and the `@functools.lru_cache(maxsize=None)` decorator plus the updated docstring are new — the function body is unchanged.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd analyzer && pytest tests/compliance/ -v`
Expected: PASS (all tests, including the new one)

- [ ] **Step 5: Write the failing API tests**

This project's API tests use Jest, not Vitest — use Jest's globals directly (no import needed, matching every other `api/tests/*.test.ts` file):

```typescript
// api/tests/services/analysisCache.test.ts
import {
  buildCacheKey,
  clearAnalysisCache,
  getCachedAnalysis,
  setCachedAnalysis,
} from '../../src/services/analysisCache';

beforeEach(() => {
  clearAnalysisCache();
});

describe('analysisCache', () => {
  it('returns undefined for a key that was never set', () => {
    expect(getCachedAnalysis('missing')).toBeUndefined();
  });

  it('returns the cached value for a key that was set', () => {
    const result = { risk_score: { overall: 1, permissiveness: 0, exposure: 0, compliance_violations: 0, unused: 0 }, findings: [] };
    setCachedAnalysis('key-1', result);
    expect(getCachedAnalysis('key-1')).toEqual(result);
  });

  it('clearAnalysisCache empties all entries', () => {
    setCachedAnalysis('key-1', { risk_score: { overall: 1, permissiveness: 0, exposure: 0, compliance_violations: 0, unused: 0 }, findings: [] });
    clearAnalysisCache();
    expect(getCachedAnalysis('key-1')).toBeUndefined();
  });

  it('buildCacheKey scopes by policy id, content hash, and frameworks', () => {
    const keyA = buildCacheKey('p1', 'hash1', ['cis']);
    const keyB = buildCacheKey('p2', 'hash1', ['cis']);
    const keyC = buildCacheKey('p1', 'hash2', ['cis']);
    const keyD = buildCacheKey('p1', 'hash1', ['hipaa']);
    expect(new Set([keyA, keyB, keyC, keyD]).size).toBe(4);
  });
});
```

Append to `api/tests/routes/policies.test.ts` (inside a new `describe` block, near the other analyze tests):

```typescript
describe('analysis result caching', () => {
  it('reuses the cached analyzer result for repeated analysis of the same unchanged policy', async () => {
    const app = createApp();
    const token = await registerAndLogin(app, 'cache@example.com');
    jest.spyOn(analyzerClient, 'parsePolicyViaAnalyzer').mockResolvedValue([]);

    const uploadRes = await request(app)
      .post('/api/policies/upload')
      .set('Authorization', `Bearer ${token}`)
      .field('name', 'cache-target')
      .field('source_type', 'firewall')
      .attach('file', VALID_FIREWALL_POLICY, 'rules.json');

    const analyzeSpy = jest.spyOn(analyzerClient, 'analyzeRulesViaAnalyzer').mockResolvedValue({
      risk_score: { overall: 7, permissiveness: 0, exposure: 0, compliance_violations: 0, unused: 0 },
      findings: [],
    });

    const first = await request(app)
      .post(`/api/policies/${uploadRes.body._id}/analyze`)
      .set('Authorization', `Bearer ${token}`);
    const second = await request(app)
      .post(`/api/policies/${uploadRes.body._id}/analyze`)
      .set('Authorization', `Bearer ${token}`);

    expect(first.status).toBe(201);
    expect(second.status).toBe(201);
    expect(first.body.risk_score.overall).toBe(7);
    expect(second.body.risk_score.overall).toBe(7);
    expect(analyzeSpy).toHaveBeenCalledTimes(1);
  });
});
```

Add `import { clearAnalysisCache } from '../../src/services/analysisCache';` to the top of `api/tests/routes/policies.test.ts` and call `clearAnalysisCache();` inside the existing `afterEach` block (alongside `clearTestDb()` and `jest.restoreAllMocks()`), so cache state never leaks between tests.

Append to `api/tests/middleware/errorHandler.test.ts` (extend the existing "responds with a 500" test):

```typescript
  it('logs a structured JSON error with method, path, and message', () => {
    const res = mockResponse();
    const next = jest.fn();
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const req = { method: 'GET', path: '/api/policies/1' } as Request;

    errorHandler(new Error('boom'), req, res, next);

    expect(consoleSpy).toHaveBeenCalledWith(
      expect.objectContaining({ method: 'GET', path: '/api/policies/1', message: 'boom' }),
    );
    consoleSpy.mockRestore();
  });
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `cd api && npx jest tests/services/analysisCache.test.ts tests/routes/policies.test.ts tests/middleware/errorHandler.test.ts`
Expected: FAIL — `analysisCache.ts` doesn't exist; the caching test sees `analyzeSpy` called twice; the logging test sees `console.error` called with just the `Error` object, not a structured shape.

- [ ] **Step 7: Implement**

```typescript
// api/src/services/analysisCache.ts
import type { AnalyzeResult } from './analyzerClient';

const TTL_MS = 5 * 60 * 1000;

interface CacheEntry {
  value: AnalyzeResult;
  expiresAt: number;
}

const cache = new Map<string, CacheEntry>();

export function buildCacheKey(policyId: string, contentHash: string, frameworks: string[]): string {
  return `${policyId}:${contentHash}:${frameworks.slice().sort().join(',')}`;
}

export function getCachedAnalysis(key: string): AnalyzeResult | undefined {
  const entry = cache.get(key);
  if (!entry) return undefined;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return undefined;
  }
  return entry.value;
}

export function setCachedAnalysis(key: string, value: AnalyzeResult): void {
  cache.set(key, { value, expiresAt: Date.now() + TTL_MS });
}

export function clearAnalysisCache(): void {
  cache.clear();
}
```

Modify `api/src/models/Policy.ts` — add `content_hash` to the interface and schema:

```typescript
export interface PolicyDocument extends Document {
  user_id: string;
  name: string;
  description: string;
  source_type: 'aws' | 'firewall' | 'iam';
  raw_content: string;
  normalized_rules: NormalizedRule[];
  content_hash: string;
  tags: string[];
  created_at: Date;
  updated_at: Date;
}
```

```typescript
const PolicySchema = new Schema<PolicyDocument>(
  {
    user_id: { type: String, required: true },
    name: { type: String, required: true },
    description: { type: String, default: '' },
    source_type: {
      type: String,
      enum: ['aws', 'firewall', 'iam'],
      required: true,
    },
    raw_content: { type: String, required: true },
    normalized_rules: { type: [NormalizedRuleSchema], default: [] },
    content_hash: { type: String, required: true },
    tags: { type: [String], default: [] },
  },
  { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } },
);

PolicySchema.index({ user_id: 1, created_at: -1 });
PolicySchema.index({ content_hash: 1 });
```

Modify `api/src/routes/policies.ts` — compute the hash at upload time and use the cache during analyze. Add to the imports:

```typescript
import { createHash } from 'crypto';
import { buildCacheKey, getCachedAnalysis, setCachedAnalysis } from '../services/analysisCache';
```

In the upload handler, right before `Policy.create({...})`, add:

```typescript
      const content_hash = createHash('sha256').update(JSON.stringify(normalized_rules)).digest('hex');
```

and add `content_hash,` to the `Policy.create({...})` call's object (alongside `raw_content`, `normalized_rules`, etc.).

Replace the body of the `POST /:id/analyze` handler's try block:

```typescript
  try {
    const cacheKey = buildCacheKey(policy.id, policy.content_hash, complianceFrameworks);
    const cached = getCachedAnalysis(cacheKey);

    emitProgress(policy.id, 'sending_to_analyzer', 25);
    const { risk_score, findings } = cached ?? (await analyzeRulesViaAnalyzer(policy.normalized_rules, complianceFrameworks));
    if (!cached) setCachedAnalysis(cacheKey, { risk_score, findings });
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
```

Modify `api/src/middleware/errorHandler.ts`:

```typescript
import { NextFunction, Request, Response } from 'express';

export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json({ error: 'Not found' });
}

export function errorHandler(
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (res.headersSent) {
    next(err);
    return;
  }
  console.error({
    timestamp: new Date().toISOString(),
    method: req.method,
    path: req.path,
    message: err.message,
    stack: err.stack,
  });
  res.status(500).json({ error: 'Internal server error' });
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd api && npx jest`
Expected: PASS — all suites, including the three modified/new ones. Existing upload tests that assert on the full `Policy` response body (e.g. `expect(res.body.normalized_rules).toHaveLength(1)`) are unaffected since `content_hash` is an additive field.

- [ ] **Step 9: Run full analyzer and API suites with coverage, then verify both builds**

Run: `cd analyzer && pytest -v --cov=src --cov-report=term-missing` — expect 100% still holds (the cache decorator doesn't add untested branches beyond what the new test already covers).
Run: `cd api && npx jest --coverage` — expect coverage still comfortably above 75%.
Run: `cd api && npm run build` — expect PASS.

- [ ] **Step 10: Commit**

```bash
git add api/src/models/Policy.ts api/src/services/analysisCache.ts api/src/routes/policies.ts api/src/middleware/errorHandler.ts analyzer/src/compliance/loader.py api/tests/services/analysisCache.test.ts api/tests/routes/policies.test.ts api/tests/middleware/errorHandler.test.ts analyzer/tests/compliance/test_loader.py
git commit -m "perf: optimize MongoDB queries and caching"
```

---

### Task 2: Performance tests and critical-journey E2E tests

**Files:**
- Create: `analyzer/tests/test_performance.py`
- Create: `api/tests/e2e/criticalJourneys.test.ts`

**Interfaces:** none new — this task only adds tests exercising existing code paths under realistic scale and across full multi-step user journeys.

- [ ] **Step 1: Write the analyzer performance test**

```python
# analyzer/tests/test_performance.py
"""Performance tests validating the response-time targets published in
CLAUDE.md/README.md: 100 rules <1s, 500 rules <3s, 1000+ rules <5s.
"""
import time
from datetime import datetime, timezone

from src.compliance import load_ruleset, matches
from src.detectors.conflicts import detect_conflicts
from src.detectors.orphaned import detect_orphaned
from src.detectors.permissiveness import detect_permissiveness
from src.detectors.risk_scorer import score_rules
from src.models import Endpoint, NormalizedRule, PortRange


def _generate_rules(count: int) -> list[NormalizedRule]:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rules = []
    for i in range(count):
        rules.append(
            NormalizedRule(
                id=f"rule-{i}",
                source_type="firewall",
                source_id=f"fw-{i % 10}",
                protocol="tcp",
                port_range=PortRange(start=1000 + i, end=1000 + i),
                direction="ingress" if i % 2 == 0 else "egress",
                action="allow" if i % 3 != 0 else "deny",
                source=Endpoint(type="cidr", value=f"10.{i % 256}.0.0/24"),
                destination=Endpoint(type="cidr", value=f"10.{(i + 1) % 256}.0.0/24"),
                created_at=now,
                modified_at=now,
                description=f"rule {i}",
                tags={},
            )
        )
    return rules


def _run_full_analysis(rules: list[NormalizedRule]) -> None:
    as_of = datetime.now(timezone.utc).replace(tzinfo=None)
    for rule in rules:
        detect_permissiveness(rule)
        detect_orphaned(rule, as_of=as_of)
    detect_conflicts(rules)
    ruleset = load_ruleset("cis")
    for rule in rules:
        for compliance_rule in ruleset:
            matches(rule, compliance_rule)
    score_rules(rules, as_of=as_of)


def test_analyzes_100_rules_under_one_second():
    rules = _generate_rules(100)
    start = time.perf_counter()
    _run_full_analysis(rules)
    assert time.perf_counter() - start < 1.0


def test_analyzes_500_rules_under_three_seconds():
    rules = _generate_rules(500)
    start = time.perf_counter()
    _run_full_analysis(rules)
    assert time.perf_counter() - start < 3.0


def test_analyzes_1000_rules_under_five_seconds():
    rules = _generate_rules(1000)
    start = time.perf_counter()
    _run_full_analysis(rules)
    assert time.perf_counter() - start < 5.0
```

- [ ] **Step 2: Run the performance test**

Run: `cd analyzer && pytest tests/test_performance.py -v`
Expected: PASS — these thresholds are generous relative to the pure-Python pairwise conflict check's O(n²) worst case at n=1000 (~500k comparisons of cheap field checks), which comfortably finishes in well under a second on typical hardware.

- [ ] **Step 3: Write the critical-journey E2E tests**

```typescript
// api/tests/e2e/criticalJourneys.test.ts
import request from 'supertest';
import { createApp } from '../../src/app';
import { clearTestDb, connectTestDb, disconnectTestDb } from '../helpers/testDb';
import { clearAnalysisCache } from '../../src/services/analysisCache';
import { VALID_FIREWALL_POLICY } from '../helpers/fixtures';
import * as analyzerClient from '../../src/services/analyzerClient';

beforeAll(async () => {
  await connectTestDb();
});

afterEach(async () => {
  await clearTestDb();
  clearAnalysisCache();
  jest.restoreAllMocks();
});

afterAll(async () => {
  await disconnectTestDb();
});

describe('critical journey: upload, analyze, retrieve, report, delete', () => {
  it('walks a policy through its full lifecycle', async () => {
    const app = createApp();

    const registerRes = await request(app)
      .post('/api/auth/register')
      .send({ email: 'journey1@example.com', password: 'password123' });
    expect(registerRes.status).toBe(201);
    const token = registerRes.body.token as string;

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

    const uploadRes = await request(app)
      .post('/api/policies/upload')
      .set('Authorization', `Bearer ${token}`)
      .field('name', 'journey-policy')
      .field('source_type', 'firewall')
      .attach('file', VALID_FIREWALL_POLICY, 'rules.json');
    expect(uploadRes.status).toBe(201);
    const policyId = uploadRes.body._id as string;

    const listRes = await request(app).get('/api/policies').set('Authorization', `Bearer ${token}`);
    expect(listRes.body).toHaveLength(1);

    jest.spyOn(analyzerClient, 'analyzeRulesViaAnalyzer').mockResolvedValue({
      risk_score: { overall: 88, permissiveness: 100, exposure: 100, compliance_violations: 50, unused: 0 },
      findings: [
        {
          type: 'overly_permissive',
          severity: 'critical',
          rule_id: 'r1',
          description: 'Allows SSH from anywhere',
          recommendation: 'Restrict source CIDR',
        },
      ],
    });

    const analyzeRes = await request(app)
      .post(`/api/policies/${policyId}/analyze`)
      .set('Authorization', `Bearer ${token}`);
    expect(analyzeRes.status).toBe(201);
    expect(analyzeRes.body.risk_score.overall).toBe(88);
    const analysisId = analyzeRes.body._id as string;

    const getAnalysisRes = await request(app)
      .get(`/api/analyses/${analysisId}`)
      .set('Authorization', `Bearer ${token}`);
    expect(getAnalysisRes.status).toBe(200);
    expect(getAnalysisRes.body.findings).toHaveLength(1);

    const reportRes = await request(app)
      .get(`/api/analyses/${analysisId}/report`)
      .set('Authorization', `Bearer ${token}`);
    expect(reportRes.status).toBe(200);
    expect(reportRes.headers['content-type']).toBe('application/pdf');
    expect(reportRes.body.subarray(0, 4).toString()).toBe('%PDF');

    const deleteRes = await request(app)
      .delete(`/api/policies/${policyId}`)
      .set('Authorization', `Bearer ${token}`);
    expect(deleteRes.status).toBe(204);

    const listAfterDeleteRes = await request(app).get('/api/policies').set('Authorization', `Bearer ${token}`);
    expect(listAfterDeleteRes.body).toHaveLength(0);
  });
});

describe('critical journey: authentication failures', () => {
  it('rejects protected routes without a token, with a wrong password, and with a garbage token', async () => {
    const app = createApp();

    const noTokenRes = await request(app).get('/api/policies');
    expect(noTokenRes.status).toBe(401);

    await request(app).post('/api/auth/register').send({ email: 'journey2@example.com', password: 'password123' });
    const wrongPasswordRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'journey2@example.com', password: 'wrong-password' });
    expect(wrongPasswordRes.status).toBe(401);

    const garbageTokenRes = await request(app)
      .get('/api/policies')
      .set('Authorization', 'Bearer not-a-real-token');
    expect(garbageTokenRes.status).toBe(401);
  });
});

describe('critical journey: cross-user isolation', () => {
  it('prevents every cross-user access path on a shared policy', async () => {
    const app = createApp();

    const ownerRes = await request(app)
      .post('/api/auth/register')
      .send({ email: 'owner@example.com', password: 'password123' });
    const otherRes = await request(app)
      .post('/api/auth/register')
      .send({ email: 'intruder@example.com', password: 'password123' });
    const ownerToken = ownerRes.body.token as string;
    const otherToken = otherRes.body.token as string;

    jest.spyOn(analyzerClient, 'parsePolicyViaAnalyzer').mockResolvedValue([]);
    const uploadRes = await request(app)
      .post('/api/policies/upload')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('name', 'owners-policy')
      .field('source_type', 'firewall')
      .attach('file', VALID_FIREWALL_POLICY, 'rules.json');
    const policyId = uploadRes.body._id as string;

    jest.spyOn(analyzerClient, 'analyzeRulesViaAnalyzer').mockResolvedValue({
      risk_score: { overall: 1, permissiveness: 0, exposure: 0, compliance_violations: 0, unused: 0 },
      findings: [],
    });
    const analyzeRes = await request(app)
      .post(`/api/policies/${policyId}/analyze`)
      .set('Authorization', `Bearer ${ownerToken}`);
    const analysisId = analyzeRes.body._id as string;

    const getPolicyAsOther = await request(app).get(`/api/policies/${policyId}`).set('Authorization', `Bearer ${otherToken}`);
    expect(getPolicyAsOther.status).toBe(403);

    const deleteAsOther = await request(app).delete(`/api/policies/${policyId}`).set('Authorization', `Bearer ${otherToken}`);
    expect(deleteAsOther.status).toBe(403);

    const analyzeAsOther = await request(app)
      .post(`/api/policies/${policyId}/analyze`)
      .set('Authorization', `Bearer ${otherToken}`);
    expect(analyzeAsOther.status).toBe(403);

    const getAnalysisAsOther = await request(app).get(`/api/analyses/${analysisId}`).set('Authorization', `Bearer ${otherToken}`);
    expect(getAnalysisAsOther.status).toBe(403);

    const getReportAsOther = await request(app).get(`/api/analyses/${analysisId}/report`).set('Authorization', `Bearer ${otherToken}`);
    expect(getReportAsOther.status).toBe(403);

    const listAsOther = await request(app).get('/api/policies').set('Authorization', `Bearer ${otherToken}`);
    expect(listAsOther.body).toEqual([]);
  });
});

describe('critical journey: malformed and oversized upload rejection', () => {
  it('rejects bad uploads and leaves no orphaned policy documents', async () => {
    const app = createApp();
    const registerRes = await request(app)
      .post('/api/auth/register')
      .send({ email: 'journey4@example.com', password: 'password123' });
    const token = registerRes.body.token as string;

    const missingMetadataRes = await request(app)
      .post('/api/policies/upload')
      .set('Authorization', `Bearer ${token}`)
      .field('source_type', 'firewall')
      .attach('file', VALID_FIREWALL_POLICY, 'rules.json');
    expect(missingMetadataRes.status).toBe(400);

    const big = Buffer.alloc(11 * 1024 * 1024, 1);
    const oversizedRes = await request(app)
      .post('/api/policies/upload')
      .set('Authorization', `Bearer ${token}`)
      .field('name', 'too-big')
      .field('source_type', 'firewall')
      .attach('file', big, 'rules.json');
    expect(oversizedRes.status).toBe(413);

    jest.spyOn(analyzerClient, 'parsePolicyViaAnalyzer').mockRejectedValue(new Error('File could not be parsed as JSON or YAML'));
    const parseFailureRes = await request(app)
      .post('/api/policies/upload')
      .set('Authorization', `Bearer ${token}`)
      .field('name', 'malformed')
      .field('source_type', 'firewall')
      .attach('file', VALID_FIREWALL_POLICY, 'rules.json');
    expect(parseFailureRes.status).toBe(400);

    const listRes = await request(app).get('/api/policies').set('Authorization', `Bearer ${token}`);
    expect(listRes.body).toEqual([]);
  });
});
```

- [ ] **Step 4: Run the E2E tests**

Run: `cd api && npx jest tests/e2e/criticalJourneys.test.ts -v`
Expected: PASS (4 tests, one per journey)

- [ ] **Step 5: Run the full suites once more with coverage**

Run: `cd analyzer && pytest -v --cov=src --cov-report=term-missing`
Run: `cd api && npx jest --coverage`
Expected: all tests pass; coverage remains comfortably above each service's target (analyzer 85%+, API 75%+).

- [ ] **Step 6: Commit**

```bash
git add analyzer/tests/test_performance.py api/tests/e2e/
git commit -m "test: add comprehensive test suite (85% coverage)"
```

---

### Task 3: Real documentation

**Files:**
- Modify: `docs/api.md`
- Modify: `docs/user-guide.md`
- Create: `CONTRIBUTING.md`
- Modify: `README.md`

**Interfaces:** none — documentation only.

- [ ] **Step 1: Replace `docs/api.md`**

```markdown
# API Documentation

Base URL (local dev): `http://localhost:5000`. All `/api/*` routes except
`/api/auth/register` and `/api/auth/login` require an `Authorization: Bearer
<token>` header. Tokens are issued by register/login and expire after 24
hours; refresh with `POST /api/auth/refresh`.

## Authentication

### `POST /api/auth/register`
Body: `{ "email": string, "password": string (min 8 chars), "name"?: string }`
Response: `201 { "token": string }`. `409` if the email is already registered.

### `POST /api/auth/login`
Body: `{ "email": string, "password": string }`
Response: `200 { "token": string }`. `401` on invalid credentials.

### `POST /api/auth/refresh`
No body. Requires a valid existing token. Response: `200 { "token": string }`.

## Policies

All policy routes require auth and only ever operate on the requesting
user's own policies — cross-user access returns `403`, not `404`, so
resource existence is never leaked to non-owners.

### `POST /api/policies/upload`
`multipart/form-data`: `name` (string), `source_type` (`aws` | `firewall` |
`iam`), `file` (the policy export). `aws` maps to the analyzer's
`security_group` parser, `iam` maps to `iam_policy`, `firewall` is used
as-is — this generic parser also covers GCP-style firewall exports well
enough that no separate GCP parser exists.
Response: `201` with the created `Policy` document (including
`normalized_rules`). `400` on missing fields or a file the analyzer can't
parse. `413` if the file exceeds `MAX_FILE_SIZE` (default 10MB).

### `GET /api/policies`
Response: `200` — array of the requesting user's `Policy` documents, newest
first.

### `GET /api/policies/:id`
Response: `200` with the `Policy`. `404` if it doesn't exist, `403` if it
belongs to another user.

### `DELETE /api/policies/:id`
Response: `204`. Same `404`/`403` rules as above.

### `POST /api/policies/:id/analyze`
Triggers analysis of the policy's `normalized_rules` against the CIS,
HIPAA, and PCI-DSS compliance rulesets, and stores the result. Emits
WebSocket progress events (see below) while running. Repeated analyze
calls for a policy whose content hasn't changed reuse the cached analyzer
result rather than recomputing it. Response: `201` with the created
`Analysis` document. `502` if the analyzer service call fails.

## Analyses

### `GET /api/analyses/:id`
Response: `200` with the `Analysis` (`risk_score`, `findings`,
`generated_at`). `403`/`404` follow the same ownership rules as policies,
resolved via the analysis's parent policy.

### `GET /api/analyses/:id/report`
Response: `200`, `Content-Type: application/pdf` — a generated PDF report
containing the risk score breakdown and every finding with its
recommendation.

## Real-time analysis progress

Connect a Socket.io client to the API's base URL with `path: '/ws/analyze'`,
then emit `join` with the policy ID to subscribe to that policy's progress
room. The server emits `progress` events shaped `{ stage: string, percent:
number }` as an analysis proceeds (`sending_to_analyzer` → 25,
`scoring_complete` → 75, `complete` → 100, or `failed` → 100 on error).

## Compliance rules

`GET /api/compliance-rules` is mounted but not yet implemented (`501`) —
the three bundled frameworks (CIS, HIPAA, PCI-DSS) and custom ruleset
loading already exist inside the analyzer service (`src/compliance/`) and
are used directly by the analyze endpoint; exposing them as their own
CRUD API was out of scope for this project's phases.

## Errors

Every error response is `{ "error": string }` (validation errors from
`POST /api/auth/register` additionally include a `details` field with
per-field messages). `500` responses are logged server-side as structured
JSON (`timestamp`, `method`, `path`, `message`, `stack`) and never leak
internal details to the client.
```

- [ ] **Step 2: Replace `docs/user-guide.md`**

```markdown
# User Guide

## 1. Create an account

Open the app (`http://localhost:3000` by default) — you're redirected to
**Log in**. Follow the "Register" link, enter an email and an 8+ character
password, and submit. You're logged in immediately and land on the
**Policies** page.

## 2. Upload a policy

On the Policies page, fill in the upload form:
- **Policy name** — any label you'll recognize later.
- **Source type** — `AWS Security Group` for a `describe-security-groups`
  JSON export, `IAM Policy` for a simplified IAM policy document, or
  `Firewall` for the generic YAML/JSON rule format (also used for
  GCP-style exports).
- **File** — the export file itself.

Submit, and the parsed policy appears in the table below with its rule
count. If the file is malformed, too large (10MB default limit), or uses
an unsupported source type, an error message explains why — nothing is
saved.

## 3. Run an analysis

Click a policy's name in the table to trigger analysis. This calls the
Python analysis engine, which checks every rule for overly permissive
access, conflicts with other rules (shadowing, redundancy, contradiction),
staleness/orphaned status, and violations of the CIS, HIPAA, and PCI-DSS
compliance rulesets — then redirects you to that analysis's dashboard.

## 4. Read the dashboard

- **Risk gauge** — the overall 0-100 score plus its four components
  (permissiveness, exposure, compliance violations, unused).
- **Compliance chart** — a bar chart of compliance-violation findings by
  severity.
- **Risk matrix** — a scatter plot of each finding's exposure (does it
  touch a critical port like 22, 3389, or 5432) against its severity.
- **Network diagram** — an interactive graph of the policy's traffic:
  nodes are source/destination endpoints, edges are rules, red edges have
  findings attached. Check "Critical only" to dim everything but
  critical-severity edges, click an edge to open its rule detail panel, or
  use "Export PNG" to save the current layout as an image.
- **Findings table** — every finding, filterable by severity and type via
  the controls above it, sortable by clicking the Severity or Type column
  header. Click a row to open that rule's detail panel (protocol,
  direction, action, ports, source/destination, description).

## 5. Export a report

From the API directly (a dedicated UI export button is a natural next
addition, but isn't wired up yet): `GET /api/analyses/:id/report` with
your bearer token returns a PDF containing the risk score breakdown and
every finding with its recommendation.

## 6. Delete a policy

Click "Delete" next to a policy in the table. This also removes it from
your list immediately; its past analyses remain queryable by ID but are no
longer reachable through the policy list.
```

- [ ] **Step 3: Create `CONTRIBUTING.md`**

```markdown
# Contributing

## Workflow

1. Branch off `main` (`feat/...`, `fix/...`, matching the change type).
2. Follow the existing TDD pattern in this repo: write the failing test
   first, then the minimal implementation, then verify it passes.
3. Commit using [Conventional Commits](https://www.conventionalcommits.org/)
   (`feat:`, `fix:`, `test:`, `docs:`, `chore:`, `perf:`, `ci:`,
   `refactor:`). Write commit messages in normal prose — no AI/LLM
   attribution anywhere, ever.
4. Keep coverage at or above each service's target: analyzer 85%+, API
   75%+, frontend 60%+.
5. Open a PR against `main` with a clear description of what changed and
   why.

## Local setup

See the Quick Start section in `README.md` for Docker Compose and local
per-service setup instructions.

## Project structure

- `analyzer/` — Python/FastAPI analysis engine. Pure functions in
  `src/parsers/`, `src/detectors/`, `src/compliance/`; `src/main.py` is a
  thin HTTP wrapper around them. Follow the existing style: typed
  function signatures, pydantic models for structured data, a short
  module docstring only where the WHY isn't obvious from the code.
- `api/` — Node/Express/TypeScript API gateway. Routes stay thin;
  business logic that isn't a one-line database call belongs in
  `src/services/`.
- `frontend/` — React/TypeScript/Tailwind UI. Components live in
  `src/components/` (reusable, presentational), pages in `src/pages/`
  (route-level, own their data fetching via the hooks in `src/hooks/`).

## Adding a new compliance framework

Add a JSON file to `analyzer/src/compliance/rulesets/`, following the
shape of the existing `cis.json`/`hipaa.json`/`pci_dss.json` files, and
add the framework name to `_BUNDLED_FRAMEWORKS` in
`analyzer/src/compliance/loader.py`. No API changes are needed — the
analyze endpoint already accepts a `compliance_frameworks` list.

## Adding a new rule source format

Add a parser module to `analyzer/src/parsers/` that exports a
`parse_<name>(raw: bytes) -> list[NormalizedRule]` function following the
existing parsers' shape (validate size, parse JSON/YAML, raise
`ParserError` on anything malformed), then register it in
`_PARSERS` in `analyzer/src/parsers/__init__.py`.

## Reporting issues

Open a GitHub issue with reproduction steps, expected vs. actual
behavior, and which service (analyzer/api/frontend) is affected.
```

- [ ] **Step 4: Correct three inaccurate claims in `README.md`**

The "Policy Upload & Parsing" feature bullet overclaims first-class GCP
support (only AWS/generic-firewall/IAM parsers exist; the generic parser
happens to also cover GCP-style exports, per a deliberate scope decision
— it isn't a dedicated GCP parser). The API Endpoints section lists a
`POST /api/compliance-rules` that was never built (compliance frameworks
are used directly by the analyzer, not exposed as their own CRUD API) and
a WebSocket path with the wrong shape. Fix all three:

```markdown
- **Policy Upload & Parsing:** Support AWS Security Groups, generic YAML/JSON firewall rules (also covers GCP-style exports), and IAM policies
```

(replaces the original "AWS Security Groups, GCP Firewall rules, and generic YAML/JSON formats" bullet)

```markdown
### Compliance
- `GET /api/compliance-rules` - not yet implemented; CIS/HIPAA/PCI-DSS frameworks are used directly by the analyze endpoint
```

(replaces the original "Compliance" section, which listed both a `GET` and a `POST /api/compliance-rules`)

```markdown
### Analysis
- `POST /api/policies/:id/analyze` - Trigger analysis
- `WS` (Socket.io, path `/ws/analyze`, join room by policy ID) - Real-time progress updates
- `GET /api/analyses/:id` - Get analysis results
- `GET /api/analyses/:id/report` - Generate PDF report
```

(replaces the original "Analysis" section's `WS /ws/analyze/:id` line)

- [ ] **Step 5: Commit**

```bash
git add docs/api.md docs/user-guide.md CONTRIBUTING.md README.md
git commit -m "docs: add API documentation and user guide"
```

---

### Task 4: GitHub Actions CI

**Files:**
- Create: `.github/workflows/test.yml`

**Interfaces:** none — CI configuration only.

- [ ] **Step 1: Create the workflow**

```yaml
# .github/workflows/test.yml
name: Test

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  analyzer:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: analyzer
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pytest -v --cov=src --cov-report=term-missing

  api:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: api
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          cache-dependency-path: api/package-lock.json
      - run: npm ci
      - run: npm run build
      - run: npx jest --coverage

  frontend:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: frontend
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          cache-dependency-path: frontend/package-lock.json
      - run: npm ci
      - run: npm run build
      - run: npx vitest run --coverage
```

- [ ] **Step 2: Validate the workflow YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/test.yml'))" && echo valid`
Expected: `valid` — this project has no `act`/local GitHub Actions runner available, so YAML syntax validation plus a careful manual review (correct `working-directory`, correct install/build/test commands matching each service's actual `package.json`/`requirements.txt`) is the verification available in this environment; the workflow will get its first real execution on the next push to GitHub.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/test.yml
git commit -m "ci: add GitHub Actions workflow for testing"
```

---

### Task 5: Docker image optimization

**Files:**
- Modify: `analyzer/Dockerfile`
- Create: `analyzer/.dockerignore`
- Create: `api/.dockerignore`

**Interfaces:** none — Docker configuration only.

- [ ] **Step 1: Convert `analyzer/Dockerfile` to a multi-stage build**

```dockerfile
# analyzer/Dockerfile
FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.11-slim
WORKDIR /app
ENV PATH=/root/.local/bin:$PATH
COPY --from=builder /root/.local /root/.local
COPY src ./src
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

(`api/Dockerfile` and `frontend/Dockerfile` are already multi-stage — no changes needed there.)

- [ ] **Step 2: Add `.dockerignore` files**

```
# analyzer/.dockerignore
venv
__pycache__
*.pyc
.pytest_cache
.coverage
htmlcov
tests
.env
```

```
# api/.dockerignore
node_modules
dist
tests
.env
.env.local
```

- [ ] **Step 3: Note the verification limitation**

No `docker` binary is available in this environment, so the Dockerfile
changes are reviewed for correctness (valid multi-stage syntax, the
`--user` pip install path matching the `PATH`/`COPY --from=builder`
target, `.dockerignore` patterns matching what each service's `.gitignore`
already excludes) but not build-verified here. Flag this to the user
rather than claiming a build was tested.

- [ ] **Step 4: Commit**

```bash
git add analyzer/Dockerfile analyzer/.dockerignore api/.dockerignore
git commit -m "chore: optimize Docker images for production"
```

- [ ] **Step 5: Push Phase 5 to GitHub**

```bash
git push origin main
```

---

## Self-Review Notes

**Spec coverage:** Milestone 5A (E2E journeys, performance tests — raw coverage % was already met by Phases 2-4) — Task 2. Milestone 5B (README/API docs/user guide/contribution guide) — Task 3. Milestone 5C (caching, MongoDB indexes, structured logging, Docker optimization; env config was already complete via `.env.example`) — Tasks 1 and 5. Milestone 5D (AI-attribution removal, conventional commits, and LICENSE were already satisfied throughout Phases 1-4; the one remaining item, CI) — Task 4. All five `prompt.txt` Milestone 5A-5D commit messages are used, in order, across Tasks 1-5.

**Placeholder scan:** no "TBD"/"TODO" strings; every step has runnable code or complete prose (for the documentation task, where "code" means the actual markdown content, not a description of what the markdown should contain).

**Type consistency:** `analysisCache.ts`'s `AnalyzeResult` type is imported from `analyzerClient.ts` (already defined in Phase 3), not redefined. `Policy.content_hash` is consumed identically by the upload handler (Task 1) and read back in the analyze handler's `buildCacheKey` call. The E2E tests (Task 2) reuse the exact same fixture (`VALID_FIREWALL_POLICY`) and mock shapes already established in Phase 3's `policies.test.ts`/`analyses.test.ts`, so there's no drift between what those tests assert and what the E2E journeys assert about the same endpoints.

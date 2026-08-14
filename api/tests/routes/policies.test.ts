import request from 'supertest';
import { createApp } from '../../src/app';
import { clearTestDb, connectTestDb, disconnectTestDb } from '../helpers/testDb';
import { VALID_FIREWALL_POLICY } from '../helpers/fixtures';
import * as analyzerClient from '../../src/services/analyzerClient';
import { clearAnalysisCache } from '../../src/services/analysisCache';

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
  it("lists only the requesting user's policies", async () => {
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

  it("returns 403 when fetching another user's policy", async () => {
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

describe('upload validation and error paths', () => {
  it('rejects an upload missing required metadata', async () => {
    const app = createApp();
    const token = await registerAndLogin(app, 'invalidmeta@example.com');

    const res = await request(app)
      .post('/api/policies/upload')
      .set('Authorization', `Bearer ${token}`)
      .field('source_type', 'firewall')
      .attach('file', VALID_FIREWALL_POLICY, 'rules.json');

    expect(res.status).toBe(400);
  });

  it('returns 400 when the analyzer fails to parse the file', async () => {
    const app = createApp();
    const token = await registerAndLogin(app, 'parsefail@example.com');
    jest.spyOn(analyzerClient, 'parsePolicyViaAnalyzer').mockRejectedValue(new Error('Unsupported source_type'));

    const res = await request(app)
      .post('/api/policies/upload')
      .set('Authorization', `Bearer ${token}`)
      .field('name', 'bad-policy')
      .field('source_type', 'firewall')
      .attach('file', VALID_FIREWALL_POLICY, 'rules.json');

    expect(res.status).toBe(400);
  });
});

describe('404 responses for nonexistent policies', () => {
  it('returns 404 for GET on a nonexistent policy', async () => {
    const app = createApp();
    const token = await registerAndLogin(app, 'get404@example.com');

    const res = await request(app)
      .get('/api/policies/000000000000000000000000')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(404);
  });

  it('returns 404 for DELETE on a nonexistent policy', async () => {
    const app = createApp();
    const token = await registerAndLogin(app, 'delete404@example.com');

    const res = await request(app)
      .delete('/api/policies/000000000000000000000000')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(404);
  });

  it('returns 404 when analyzing a nonexistent policy', async () => {
    const app = createApp();
    const token = await registerAndLogin(app, 'analyze404@example.com');

    const res = await request(app)
      .post('/api/policies/000000000000000000000000/analyze')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(404);
  });

  it("returns 403 when analyzing another user's policy", async () => {
    const app = createApp();
    const tokenA = await registerAndLogin(app, 'analyzeOwnerA@example.com');
    const tokenB = await registerAndLogin(app, 'analyzeOwnerB@example.com');
    jest.spyOn(analyzerClient, 'parsePolicyViaAnalyzer').mockResolvedValue([]);

    const uploadRes = await request(app)
      .post('/api/policies/upload')
      .set('Authorization', `Bearer ${tokenA}`)
      .field('name', 'not-yours')
      .field('source_type', 'firewall')
      .attach('file', VALID_FIREWALL_POLICY, 'rules.json');

    const res = await request(app)
      .post(`/api/policies/${uploadRes.body._id}/analyze`)
      .set('Authorization', `Bearer ${tokenB}`);

    expect(res.status).toBe(403);
  });

  it('returns 502 when the analyzer fails during analysis', async () => {
    const app = createApp();
    const token = await registerAndLogin(app, 'analyzefail@example.com');
    jest.spyOn(analyzerClient, 'parsePolicyViaAnalyzer').mockResolvedValue([]);

    const uploadRes = await request(app)
      .post('/api/policies/upload')
      .set('Authorization', `Bearer ${token}`)
      .field('name', 'fails-to-analyze')
      .field('source_type', 'firewall')
      .attach('file', VALID_FIREWALL_POLICY, 'rules.json');

    jest.spyOn(analyzerClient, 'analyzeRulesViaAnalyzer').mockRejectedValue(new Error('analyzer unreachable'));

    const res = await request(app)
      .post(`/api/policies/${uploadRes.body._id}/analyze`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(502);
  });
});

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

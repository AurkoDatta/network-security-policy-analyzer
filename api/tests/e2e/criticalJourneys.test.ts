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

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
  const registerRes = await request(app)
    .post('/api/auth/register')
    .send({ email: `analyze-${Date.now()}-${Math.random()}@example.com`, password: 'password123' });
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

    const client: Socket = ioClient(baseUrl, { path: '/ws/analyze', transports: ['websocket'] });
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

  it("returns 403 for another user's analysis", async () => {
    const app = createApp();
    const { token, policyId } = await registerAndUpload();
    const otherRes = await request(app)
      .post('/api/auth/register')
      .send({ email: `other-${Date.now()}-${Math.random()}@example.com`, password: 'password123' });

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

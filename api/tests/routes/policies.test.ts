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

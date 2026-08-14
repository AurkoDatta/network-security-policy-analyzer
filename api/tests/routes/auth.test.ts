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

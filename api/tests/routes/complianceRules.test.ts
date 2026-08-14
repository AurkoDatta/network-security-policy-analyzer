import request from 'supertest';
import { createApp } from '../../src/app';

describe('GET /api/compliance-rules', () => {
  it('returns 501 not implemented', async () => {
    const app = createApp();
    const res = await request(app).get('/api/compliance-rules');

    expect(res.status).toBe(501);
  });
});

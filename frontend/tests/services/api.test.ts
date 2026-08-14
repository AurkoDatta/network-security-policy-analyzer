import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  deletePolicy,
  getAnalysis,
  getHealth,
  getPolicy,
  listPolicies,
  loginUser,
  registerUser,
  triggerAnalysis,
  uploadPolicy,
} from '../../src/services/api';

const originalFetch = global.fetch;

afterEach(() => {
  global.fetch = originalFetch;
  vi.restoreAllMocks();
});

function mockFetchOnce(body: unknown, status = 200) {
  global.fetch = vi.fn().mockResolvedValue({
    ok: status < 400,
    status,
    json: async () => body,
  }) as unknown as typeof fetch;
}

describe('services/api', () => {
  it('getHealth fetches the health endpoint', async () => {
    mockFetchOnce({ status: 'ok', service: 'api' });
    const result = await getHealth();
    expect(result).toEqual({ status: 'ok', service: 'api' });
  });

  it('loginUser posts credentials', async () => {
    mockFetchOnce({ token: 't1' });
    const result = await loginUser('a@example.com', 'pw');
    expect(result).toEqual({ token: 't1' });
  });

  it('registerUser posts registration data', async () => {
    mockFetchOnce({ token: 't2' });
    const result = await registerUser('a@example.com', 'pw', 'Name');
    expect(result).toEqual({ token: 't2' });
  });

  it('listPolicies fetches with the token', async () => {
    mockFetchOnce([]);
    const result = await listPolicies('tok');
    expect(result).toEqual([]);
  });

  it('uploadPolicy posts form data with the token', async () => {
    mockFetchOnce({ _id: 'p1' });
    const result = await uploadPolicy('tok', new FormData());
    expect(result).toEqual({ _id: 'p1' });
  });

  it('deletePolicy sends a DELETE request', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 204 }) as unknown as typeof fetch;
    const result = await deletePolicy('tok', 'p1');
    expect(result).toBeUndefined();
  });

  it('getPolicy fetches a single policy', async () => {
    mockFetchOnce({ _id: 'p1' });
    const result = await getPolicy('tok', 'p1');
    expect(result).toEqual({ _id: 'p1' });
  });

  it('getAnalysis fetches a single analysis', async () => {
    mockFetchOnce({ _id: 'a1' });
    const result = await getAnalysis('tok', 'a1');
    expect(result).toEqual({ _id: 'a1' });
  });

  it('triggerAnalysis posts to the analyze endpoint', async () => {
    mockFetchOnce({ _id: 'a1' });
    const result = await triggerAnalysis('tok', 'p1');
    expect(result).toEqual({ _id: 'a1' });
  });
});

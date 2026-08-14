import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiFetch, ApiError } from '../../src/lib/apiClient';

const originalFetch = global.fetch;

afterEach(() => {
  global.fetch = originalFetch;
  vi.restoreAllMocks();
});

describe('apiFetch', () => {
  it('attaches the bearer token when provided', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ hello: 'world' }),
    }) as unknown as typeof fetch;

    await apiFetch('/api/policies', {}, 'token-123');

    const [, options] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const headers = options.headers as Headers;
    expect(headers.get('Authorization')).toBe('Bearer token-123');
  });

  it('does not set an Authorization header when no token is given', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({}),
    }) as unknown as typeof fetch;

    await apiFetch('/api/health');

    const [, options] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const headers = options.headers as Headers;
    expect(headers.has('Authorization')).toBe(false);
  });

  it('returns undefined for 204 No Content responses', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 204 }) as unknown as typeof fetch;

    const result = await apiFetch('/api/policies/1');

    expect(result).toBeUndefined();
  });

  it('throws an ApiError with the server message on failure', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      json: async () => ({ error: 'Forbidden' }),
    }) as unknown as typeof fetch;

    await expect(apiFetch('/api/policies/1')).rejects.toThrow('Forbidden');
    await expect(apiFetch('/api/policies/1')).rejects.toBeInstanceOf(ApiError);
  });

  it('does not set Content-Type for FormData bodies', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({}) }) as unknown as typeof fetch;

    await apiFetch('/api/policies/upload', { method: 'POST', body: new FormData() });

    const [, options] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const headers = options.headers as Headers;
    expect(headers.has('Content-Type')).toBe(false);
  });
});

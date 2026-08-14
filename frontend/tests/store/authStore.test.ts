import { beforeEach, describe, expect, it } from 'vitest';
import { useAuthStore } from '../../src/store/authStore';

describe('authStore', () => {
  beforeEach(() => {
    useAuthStore.setState({ token: null });
    localStorage.clear();
  });

  it('starts with no token', () => {
    expect(useAuthStore.getState().token).toBeNull();
  });

  it('sets and clears the token', () => {
    useAuthStore.getState().setToken('abc123');
    expect(useAuthStore.getState().token).toBe('abc123');

    useAuthStore.getState().setToken(null);
    expect(useAuthStore.getState().token).toBeNull();
  });
});

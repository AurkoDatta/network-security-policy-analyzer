import { apiFetch } from '../lib/apiClient';

const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:5000';

export interface HealthResponse {
  status: string;
  service: string;
}

export async function getHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE_URL}/health`);
  return res.json();
}

export async function loginUser(email: string, password: string): Promise<{ token: string }> {
  return apiFetch('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) });
}

export async function registerUser(
  email: string,
  password: string,
  name?: string,
): Promise<{ token: string }> {
  return apiFetch('/api/auth/register', { method: 'POST', body: JSON.stringify({ email, password, name }) });
}

import { apiFetch } from '../lib/apiClient';
import type { Analysis, Policy } from '../types/api';

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

export async function listPolicies(token: string): Promise<Policy[]> {
  return apiFetch('/api/policies', {}, token);
}

export async function uploadPolicy(token: string, formData: FormData): Promise<Policy> {
  return apiFetch('/api/policies/upload', { method: 'POST', body: formData }, token);
}

export async function deletePolicy(token: string, id: string): Promise<void> {
  return apiFetch(`/api/policies/${id}`, { method: 'DELETE' }, token);
}

export async function getPolicy(token: string, id: string): Promise<Policy> {
  return apiFetch(`/api/policies/${id}`, {}, token);
}

export async function getAnalysis(token: string, id: string): Promise<Analysis> {
  return apiFetch(`/api/analyses/${id}`, {}, token);
}

export async function triggerAnalysis(token: string, policyId: string): Promise<Analysis> {
  return apiFetch(`/api/policies/${policyId}/analyze`, { method: 'POST' }, token);
}

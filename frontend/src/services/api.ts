const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:5000';

export interface HealthResponse {
  status: string;
  service: string;
}

export async function getHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE_URL}/health`);
  return res.json();
}

import { NormalizedRule, RiskScore } from '../models/NormalizedRule';
import { Finding } from '../models/Analysis';
import { env } from '../config/env';

export interface AnalyzeResult {
  risk_score: RiskScore;
  findings: Finding[];
}

async function readErrorDetail(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: string };
    return body.detail ?? `Analyzer request failed with status ${response.status}`;
  } catch {
    return `Analyzer request failed with status ${response.status}`;
  }
}

export async function parsePolicyViaAnalyzer(
  raw: Buffer,
  sourceType: string,
  filename: string,
): Promise<NormalizedRule[]> {
  const form = new FormData();
  form.append('source_type', sourceType);
  form.append('file', new Blob([raw]), filename);

  const response = await fetch(`${env.pythonAnalyzerUrl}/parse`, {
    method: 'POST',
    body: form,
  });

  if (!response.ok) {
    throw new Error(await readErrorDetail(response));
  }

  return (await response.json()) as NormalizedRule[];
}

export async function analyzeRulesViaAnalyzer(
  rules: NormalizedRule[],
  complianceFrameworks: string[],
): Promise<AnalyzeResult> {
  const response = await fetch(`${env.pythonAnalyzerUrl}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rules, compliance_frameworks: complianceFrameworks }),
  });

  if (!response.ok) {
    throw new Error(await readErrorDetail(response));
  }

  return (await response.json()) as AnalyzeResult;
}

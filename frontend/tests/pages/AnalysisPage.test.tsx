import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { AnalysisPage } from '../../src/pages/AnalysisPage';
import * as analysisHooks from '../../src/hooks/useAnalysis';
import * as policyHooks from '../../src/hooks/usePolicies';
import type { Analysis, Policy } from '../../src/types/api';

vi.mock('../../src/hooks/useAnalysis');
vi.mock('../../src/hooks/usePolicies');
vi.mock('cytoscape', () => ({
  default: vi.fn(() => ({
    on: vi.fn(),
    destroy: vi.fn(),
    png: vi.fn(),
    elements: vi.fn().mockReturnValue({ removeClass: vi.fn() }),
    $: vi.fn().mockReturnValue([]),
  })),
}));

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/analyses/a1']}>
      <Routes>
        <Route path="/analyses/:id" element={<AnalysisPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('AnalysisPage', () => {
  it('shows a loading state', () => {
    vi.mocked(analysisHooks.useAnalysis).mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
    } as never);
    vi.mocked(policyHooks.usePolicy).mockReturnValue({ data: undefined } as never);

    renderPage();

    expect(screen.getByText(/loading analysis/i)).toBeInTheDocument();
  });

  it('shows an error message', () => {
    vi.mocked(analysisHooks.useAnalysis).mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new Error('boom'),
    } as never);
    vi.mocked(policyHooks.usePolicy).mockReturnValue({ data: undefined } as never);

    renderPage();

    expect(screen.getByText('boom')).toBeInTheDocument();
  });

  it('renders the full dashboard once data loads', () => {
    const analysis: Analysis = {
      _id: 'a1',
      policy_id: 'p1',
      risk_score: { overall: 10, permissiveness: 0, exposure: 0, compliance_violations: 0, unused: 0 },
      findings: [],
      generated_at: '2026-01-01T00:00:00Z',
    };
    const policy: Policy = {
      _id: 'p1',
      user_id: 'u1',
      name: 'test',
      description: '',
      source_type: 'firewall',
      normalized_rules: [],
      tags: [],
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
    };
    vi.mocked(analysisHooks.useAnalysis).mockReturnValue({ data: analysis, isLoading: false, error: null } as never);
    vi.mocked(policyHooks.usePolicy).mockReturnValue({ data: policy } as never);

    renderPage();

    expect(screen.getByRole('heading', { name: /analysis/i })).toBeInTheDocument();
  });
});

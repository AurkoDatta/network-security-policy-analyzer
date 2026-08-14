import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { RiskGauge } from '../../src/components/RiskGauge';
import type { RiskScore } from '../../src/types/api';

const SCORE: RiskScore = { overall: 72, permissiveness: 80, exposure: 60, compliance_violations: 90, unused: 10 };

describe('RiskGauge', () => {
  it('displays the overall score', () => {
    render(<RiskGauge score={SCORE} />);
    expect(screen.getByText('72')).toBeInTheDocument();
  });

  it('displays each sub-score', () => {
    render(<RiskGauge score={SCORE} />);
    expect(screen.getByText(/permissiveness/i)).toBeInTheDocument();
    expect(screen.getByText(/exposure/i)).toBeInTheDocument();
    expect(screen.getByText(/compliance/i)).toBeInTheDocument();
    expect(screen.getByText(/unused/i)).toBeInTheDocument();
  });
});

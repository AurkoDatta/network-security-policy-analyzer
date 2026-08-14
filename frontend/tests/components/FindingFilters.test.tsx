import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { FindingFilters } from '../../src/components/FindingFilters';
import type { Finding } from '../../src/types/api';

const FINDINGS: Finding[] = [
  { type: 'orphaned', severity: 'low', rule_id: 'r1', description: 'a', recommendation: 'x' },
  { type: 'overly_permissive', severity: 'critical', rule_id: 'r2', description: 'b', recommendation: 'y' },
];

describe('FindingFilters', () => {
  it('calls onFilterChange with all findings by default', () => {
    const onFilterChange = vi.fn();
    render(<FindingFilters findings={FINDINGS} onFilterChange={onFilterChange} />);

    expect(onFilterChange).toHaveBeenCalledWith(FINDINGS);
  });

  it('filters by severity', async () => {
    const onFilterChange = vi.fn();
    render(<FindingFilters findings={FINDINGS} onFilterChange={onFilterChange} />);

    await userEvent.selectOptions(screen.getByLabelText(/severity/i), 'critical');

    expect(onFilterChange).toHaveBeenLastCalledWith([FINDINGS[1]]);
  });

  it('filters by type', async () => {
    const onFilterChange = vi.fn();
    render(<FindingFilters findings={FINDINGS} onFilterChange={onFilterChange} />);

    await userEvent.selectOptions(screen.getByLabelText(/type/i), 'orphaned');

    expect(onFilterChange).toHaveBeenLastCalledWith([FINDINGS[0]]);
  });
});

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { NetworkDiagram } from '../../src/components/NetworkDiagram';
import type { Finding, NormalizedRule } from '../../src/types/api';

const mockCy = {
  on: vi.fn(),
  destroy: vi.fn(),
  png: vi.fn().mockReturnValue('data:image/png;base64,abc'),
  elements: vi.fn().mockReturnValue({ removeClass: vi.fn() }),
  $: vi.fn().mockReturnValue([{ id: () => 'r1', addClass: vi.fn() }]),
};

vi.mock('cytoscape', () => ({
  default: vi.fn(() => mockCy),
}));

const RULES: NormalizedRule[] = [
  {
    id: 'r1',
    source_type: 'firewall',
    source_id: 'fw-1',
    protocol: 'tcp',
    port_range: { start: 22, end: 22 },
    direction: 'ingress',
    action: 'allow',
    source: { type: 'cidr', value: '0.0.0.0/0' },
    destination: { type: 'cidr', value: '10.0.0.0/8' },
    created_at: '2026-01-01T00:00:00Z',
    modified_at: '2026-01-01T00:00:00Z',
    description: '',
    tags: {},
  },
];

const FINDINGS: Finding[] = [
  { type: 'overly_permissive', severity: 'critical', rule_id: 'r1', description: 'open', recommendation: 'fix' },
];

beforeEach(() => {
  vi.clearAllMocks();
});

describe('NetworkDiagram', () => {
  it('initializes cytoscape with nodes and edges derived from the rules', async () => {
    const cytoscape = (await import('cytoscape')).default;
    render(<NetworkDiagram rules={RULES} findings={FINDINGS} onSelectRule={vi.fn()} />);

    expect(cytoscape).toHaveBeenCalled();
    const config = vi.mocked(cytoscape).mock.calls[0][0] as unknown as { elements: unknown[] };
    expect(config.elements.length).toBeGreaterThan(0);
  });

  it('toggles critical-only filtering', async () => {
    render(<NetworkDiagram rules={RULES} findings={FINDINGS} onSelectRule={vi.fn()} />);

    await userEvent.click(screen.getByRole('checkbox', { name: /critical only/i }));

    expect(mockCy.elements).toHaveBeenCalled();
  });

  it('exports the graph as a PNG when the export button is clicked', async () => {
    render(<NetworkDiagram rules={RULES} findings={FINDINGS} onSelectRule={vi.fn()} />);

    await userEvent.click(screen.getByRole('button', { name: /export/i }));

    expect(mockCy.png).toHaveBeenCalled();
  });
});

import cytoscape, { type Core, type ElementDefinition } from 'cytoscape';
import { useEffect, useRef, useState } from 'react';
import type { Finding, NormalizedRule } from '../types/api';

interface NetworkDiagramProps {
  rules: NormalizedRule[];
  findings: Finding[];
  onSelectRule: (rule: NormalizedRule) => void;
}

function buildElements(rules: NormalizedRule[], findingRuleIds: Set<string>): ElementDefinition[] {
  const nodeIds = new Set<string>();
  const elements: ElementDefinition[] = [];

  for (const rule of rules) {
    const sourceId = `${rule.source.type}:${rule.source.value}`;
    const destId = `${rule.destination.type}:${rule.destination.value}`;

    if (!nodeIds.has(sourceId)) {
      nodeIds.add(sourceId);
      elements.push({ data: { id: sourceId, label: rule.source.value } });
    }
    if (!nodeIds.has(destId)) {
      nodeIds.add(destId);
      elements.push({ data: { id: destId, label: rule.destination.value } });
    }

    elements.push({
      data: {
        id: rule.id,
        source: sourceId,
        target: destId,
        label: `${rule.protocol}${rule.port_range ? `:${rule.port_range.start}` : ''}`,
      },
      classes: findingRuleIds.has(rule.id) ? 'has-finding' : undefined,
    });
  }

  return elements;
}

export function NetworkDiagram({ rules, findings, onSelectRule }: NetworkDiagramProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [criticalOnly, setCriticalOnly] = useState(false);

  const findingRuleIds = new Set(findings.map((f) => f.rule_id));
  const criticalRuleIds = new Set(findings.filter((f) => f.severity === 'critical').map((f) => f.rule_id));

  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      elements: buildElements(rules, findingRuleIds),
      style: [
        { selector: 'node', style: { label: 'data(label)', 'font-size': 8 } },
        { selector: 'edge', style: { label: 'data(label)', 'font-size': 8, 'line-color': '#94a3b8' } },
        { selector: 'edge.has-finding', style: { 'line-color': '#dc2626' } },
      ],
      layout: { name: 'cose' },
    });

    cy.on('tap', 'edge', (event) => {
      const ruleId = event.target.id();
      const rule = rules.find((r) => r.id === ruleId);
      if (rule) onSelectRule(rule);
    });

    cyRef.current = cy;
    return () => cy.destroy();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rules]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().removeClass('hidden-edge');
    if (criticalOnly) {
      cy.$(':edge').forEach((edge: { id: () => string; addClass: (c: string) => void }) => {
        if (!criticalRuleIds.has(edge.id())) edge.addClass('hidden-edge');
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [criticalOnly]);

  const handleExport = () => {
    const cy = cyRef.current;
    if (!cy) return;
    const dataUrl = cy.png({ full: true });
    const link = document.createElement('a');
    link.href = dataUrl;
    link.download = 'network-diagram.png';
    link.click();
  };

  return (
    <div className="flex flex-col gap-2 rounded border p-4">
      <div className="flex items-center justify-between">
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={criticalOnly} onChange={(e) => setCriticalOnly(e.target.checked)} />
          Critical only
        </label>
        <button type="button" onClick={handleExport} className="rounded border px-3 py-1 text-sm">
          Export PNG
        </button>
      </div>
      <div ref={containerRef} style={{ height: 400 }} />
    </div>
  );
}

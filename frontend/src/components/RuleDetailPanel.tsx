import type { NormalizedRule } from '../types/api';

interface RuleDetailPanelProps {
  rule: NormalizedRule | null;
  onClose: () => void;
}

export function RuleDetailPanel({ rule, onClose }: RuleDetailPanelProps) {
  if (!rule) return null;

  return (
    <aside className="fixed right-0 top-0 flex h-full w-80 flex-col gap-2 border-l bg-white p-4 shadow-lg">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">{rule.source_id}</h2>
        <button type="button" onClick={onClose} aria-label="close" className="text-slate-500">
          Close
        </button>
      </div>
      <p>Protocol: {rule.protocol}</p>
      <p>Direction: {rule.direction}</p>
      <p>Action: {rule.action}</p>
      {rule.port_range && (
        <p>
          Ports: {rule.port_range.start}-{rule.port_range.end}
        </p>
      )}
      <p>Source: {rule.source.value}</p>
      <p>Destination: {rule.destination.value}</p>
      {rule.description && <p>Description: {rule.description}</p>}
    </aside>
  );
}

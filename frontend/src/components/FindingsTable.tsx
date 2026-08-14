import { useMemo, useState } from 'react';
import type { Finding, Severity } from '../types/api';

interface FindingsTableProps {
  findings: Finding[];
  onSelect: (ruleId: string) => void;
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 3, high: 2, medium: 1, low: 0 };

type SortKey = 'severity' | 'type';

export function FindingsTable({ findings, onSelect }: FindingsTableProps) {
  const [sortKey, setSortKey] = useState<SortKey | null>(null);

  const sorted = useMemo(() => {
    if (!sortKey) return findings;
    return [...findings].sort((a, b) => {
      if (sortKey === 'severity') return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
      return a.type.localeCompare(b.type);
    });
  }, [findings, sortKey]);

  return (
    <table className="w-full border-collapse text-left">
      <thead>
        <tr className="border-b">
          <th className="cursor-pointer py-2" onClick={() => setSortKey('severity')} role="columnheader">
            Severity
          </th>
          <th className="cursor-pointer py-2" onClick={() => setSortKey('type')} role="columnheader">
            Type
          </th>
          <th className="py-2">Description</th>
        </tr>
      </thead>
      <tbody>
        {sorted.map((finding, index) => (
          <tr key={`${finding.rule_id}-${index}`} className="cursor-pointer border-b" onClick={() => onSelect(finding.rule_id)}>
            <td className="py-2">{finding.severity}</td>
            <td className="py-2">{finding.type}</td>
            <td className="py-2">{finding.description}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

import { useEffect, useState } from 'react';
import type { Finding, FindingType, Severity } from '../types/api';

interface FindingFiltersProps {
  findings: Finding[];
  onFilterChange: (filtered: Finding[]) => void;
}

export function FindingFilters({ findings, onFilterChange }: FindingFiltersProps) {
  const [severity, setSeverity] = useState<Severity | 'all'>('all');
  const [type, setType] = useState<FindingType | 'all'>('all');

  useEffect(() => {
    const filtered = findings.filter(
      (f) => (severity === 'all' || f.severity === severity) && (type === 'all' || f.type === type),
    );
    onFilterChange(filtered);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findings, severity, type]);

  return (
    <div className="flex gap-4">
      <label className="flex flex-col gap-1 text-sm">
        Severity
        <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity | 'all')} className="rounded border px-2 py-1">
          <option value="all">All</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </label>
      <label className="flex flex-col gap-1 text-sm">
        Type
        <select value={type} onChange={(e) => setType(e.target.value as FindingType | 'all')} className="rounded border px-2 py-1">
          <option value="all">All</option>
          <option value="overly_permissive">Overly permissive</option>
          <option value="conflict">Conflict</option>
          <option value="orphaned">Orphaned</option>
          <option value="compliance_violation">Compliance violation</option>
        </select>
      </label>
    </div>
  );
}

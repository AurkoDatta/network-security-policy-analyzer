import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useAnalysis } from '../hooks/useAnalysis';
import { FindingsTable } from '../components/FindingsTable';
import { FindingFilters } from '../components/FindingFilters';
import { RuleDetailPanel } from '../components/RuleDetailPanel';
import { RiskGauge } from '../components/RiskGauge';
import { ComplianceChart } from '../components/ComplianceChart';
import type { Finding, NormalizedRule } from '../types/api';

export function AnalysisPage() {
  const { id } = useParams<{ id: string }>();
  const { data: analysis, isLoading, error } = useAnalysis(id);
  const [filtered, setFiltered] = useState<Finding[]>([]);
  const [selectedRule, setSelectedRule] = useState<NormalizedRule | null>(null);

  if (isLoading) return <p className="p-8">Loading analysis…</p>;
  if (error) return <p className="p-8 text-red-600">{(error as Error).message}</p>;
  if (!analysis) return null;

  const handleSelect = (ruleId: string) => {
    setSelectedRule(null);
    void ruleId;
  };

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 px-4 py-8">
      <h1 className="text-2xl font-semibold">Analysis</h1>
      <div className="grid grid-cols-2 gap-4">
        <RiskGauge score={analysis.risk_score} />
        <ComplianceChart findings={analysis.findings} />
      </div>
      <FindingFilters findings={analysis.findings} onFilterChange={setFiltered} />
      <FindingsTable findings={filtered} onSelect={handleSelect} />
      <RuleDetailPanel rule={selectedRule} onClose={() => setSelectedRule(null)} />
    </div>
  );
}

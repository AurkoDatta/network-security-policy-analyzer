import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useAnalysis } from '../hooks/useAnalysis';
import { usePolicy } from '../hooks/usePolicies';
import { FindingsTable } from '../components/FindingsTable';
import { FindingFilters } from '../components/FindingFilters';
import { RuleDetailPanel } from '../components/RuleDetailPanel';
import { RiskGauge } from '../components/RiskGauge';
import { ComplianceChart } from '../components/ComplianceChart';
import { NetworkDiagram } from '../components/NetworkDiagram';
import { RiskMatrix } from '../components/RiskMatrix';
import type { Finding, NormalizedRule } from '../types/api';

export function AnalysisPage() {
  const { id } = useParams<{ id: string }>();
  const { data: analysis, isLoading, error } = useAnalysis(id);
  const { data: policy } = usePolicy(analysis?.policy_id);
  const [filtered, setFiltered] = useState<Finding[]>([]);
  const [selectedRule, setSelectedRule] = useState<NormalizedRule | null>(null);

  if (isLoading) return <p className="p-8">Loading analysis…</p>;
  if (error) return <p className="p-8 text-red-600">{(error as Error).message}</p>;
  if (!analysis) return null;

  const rules = policy?.normalized_rules ?? [];

  const handleSelectByRuleId = (ruleId: string) => {
    const rule = rules.find((r) => r.id === ruleId);
    setSelectedRule(rule ?? null);
  };

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 px-4 py-8">
      <h1 className="text-2xl font-semibold">Analysis</h1>
      <div className="grid grid-cols-2 gap-4">
        <RiskGauge score={analysis.risk_score} />
        <ComplianceChart findings={analysis.findings} />
      </div>
      <RiskMatrix findings={analysis.findings} rules={rules} />
      <NetworkDiagram rules={rules} findings={analysis.findings} onSelectRule={setSelectedRule} />
      <FindingFilters findings={analysis.findings} onFilterChange={setFiltered} />
      <FindingsTable findings={filtered} onSelect={handleSelectByRuleId} />
      <RuleDetailPanel rule={selectedRule} onClose={() => setSelectedRule(null)} />
    </div>
  );
}

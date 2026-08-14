import { CartesianGrid, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis, ZAxis } from 'recharts';
import type { Finding, NormalizedRule, Severity } from '../types/api';

interface RiskMatrixProps {
  findings: Finding[];
  rules: NormalizedRule[];
}

const SEVERITY_RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };
const CRITICAL_PORTS = new Set([22, 23, 3389, 5432, 3306, 27017, 6379, 9200, 1433]);

function exposureScore(rule: NormalizedRule | undefined): number {
  if (!rule?.port_range) return 0;
  for (let port = rule.port_range.start; port <= rule.port_range.end; port++) {
    if (CRITICAL_PORTS.has(port)) return 1;
  }
  return 0;
}

export function RiskMatrix({ findings, rules }: RiskMatrixProps) {
  if (findings.length === 0) {
    return <p className="text-slate-500">No findings to plot.</p>;
  }

  const data = findings.map((finding) => {
    const rule = rules.find((r) => r.id === finding.rule_id);
    return {
      exposure: exposureScore(rule),
      severity: SEVERITY_RANK[finding.severity],
      label: finding.rule_id,
    };
  });

  return (
    <div className="h-64 w-full rounded border p-4">
      <ResponsiveContainer width="100%" height="100%">
        <ScatterChart>
          <CartesianGrid />
          <XAxis type="number" dataKey="exposure" name="Exposure" domain={[0, 1]} />
          <YAxis type="number" dataKey="severity" name="Severity" domain={[1, 4]} />
          <ZAxis range={[80, 80]} />
          <Tooltip cursor={{ strokeDasharray: '3 3' }} />
          <Scatter data={data} fill="#dc2626" />
        </ScatterChart>
      </ResponsiveContainer>
    </div>
  );
}

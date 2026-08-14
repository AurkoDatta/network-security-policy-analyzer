import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { Finding, Severity } from '../types/api';

interface ComplianceChartProps {
  findings: Finding[];
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

export function ComplianceChart({ findings }: ComplianceChartProps) {
  const violations = findings.filter((f) => f.type === 'compliance_violation');

  if (violations.length === 0) {
    return <p className="text-slate-500">No compliance violations found.</p>;
  }

  const data = SEVERITIES.map((severity) => ({
    severity,
    count: violations.filter((f) => f.severity === severity).length,
  }));

  return (
    <div className="h-64 w-full rounded border p-4">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="severity" />
          <YAxis allowDecimals={false} />
          <Tooltip />
          <Bar dataKey="count" fill="#dc2626" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

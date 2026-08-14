import type { RiskScore } from '../types/api';

interface RiskGaugeProps {
  score: RiskScore;
}

function scoreColor(value: number): string {
  if (value >= 75) return 'text-red-600';
  if (value >= 40) return 'text-amber-600';
  return 'text-green-600';
}

export function RiskGauge({ score }: RiskGaugeProps) {
  return (
    <div className="flex flex-col gap-3 rounded border p-4">
      <div className="flex flex-col items-center">
        <span className={`text-5xl font-bold ${scoreColor(score.overall)}`}>{score.overall}</span>
        <span className="text-sm text-slate-500">Overall risk</span>
      </div>
      <dl className="grid grid-cols-2 gap-2 text-sm">
        <dt>Permissiveness</dt>
        <dd className={scoreColor(score.permissiveness)}>{score.permissiveness}</dd>
        <dt>Exposure</dt>
        <dd className={scoreColor(score.exposure)}>{score.exposure}</dd>
        <dt>Compliance violations</dt>
        <dd className={scoreColor(score.compliance_violations)}>{score.compliance_violations}</dd>
        <dt>Unused</dt>
        <dd className={scoreColor(score.unused)}>{score.unused}</dd>
      </dl>
    </div>
  );
}

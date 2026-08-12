import { Schema, model, Document, Types } from 'mongoose';
import { RiskScore, RiskScoreSchema } from './NormalizedRule';

export type FindingType =
  | 'overly_permissive'
  | 'conflict'
  | 'orphaned'
  | 'compliance_violation';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface Finding {
  type: FindingType;
  severity: Severity;
  rule_id: string;
  description: string;
  recommendation: string;
}

export interface AnalysisDocument extends Document {
  policy_id: Types.ObjectId;
  risk_score: RiskScore;
  findings: Finding[];
  generated_at: Date;
}

const FindingSchema = new Schema<Finding>(
  {
    type: {
      type: String,
      enum: ['overly_permissive', 'conflict', 'orphaned', 'compliance_violation'],
      required: true,
    },
    severity: {
      type: String,
      enum: ['critical', 'high', 'medium', 'low'],
      required: true,
    },
    rule_id: { type: String, required: true },
    description: { type: String, required: true },
    recommendation: { type: String, required: true },
  },
  { _id: false },
);

const AnalysisSchema = new Schema<AnalysisDocument>({
  policy_id: { type: Schema.Types.ObjectId, ref: 'Policy', required: true },
  risk_score: { type: RiskScoreSchema, required: true },
  findings: { type: [FindingSchema], default: [] },
  generated_at: { type: Date, default: Date.now },
});

AnalysisSchema.index({ policy_id: 1 });

export const Analysis = model<AnalysisDocument>('Analysis', AnalysisSchema);

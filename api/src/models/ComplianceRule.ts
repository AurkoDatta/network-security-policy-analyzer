import { Schema, model, Document } from 'mongoose';
import { Severity } from './Analysis';

export interface ComplianceMatcher {
  protocol?: string;
  ports?: number[];
  source?: string;
  destination?: string;
}

export interface ComplianceRuleDocument extends Document {
  framework: 'cis' | 'hipaa' | 'pci_dss' | 'custom';
  rule_id: string;
  description: string;
  matcher: ComplianceMatcher;
  severity: Severity;
}

const ComplianceMatcherSchema = new Schema<ComplianceMatcher>(
  {
    protocol: { type: String },
    ports: { type: [Number], default: undefined },
    source: { type: String },
    destination: { type: String },
  },
  { _id: false },
);

const ComplianceRuleSchema = new Schema<ComplianceRuleDocument>({
  framework: {
    type: String,
    enum: ['cis', 'hipaa', 'pci_dss', 'custom'],
    required: true,
  },
  rule_id: { type: String, required: true },
  description: { type: String, required: true },
  matcher: { type: ComplianceMatcherSchema, required: true },
  severity: {
    type: String,
    enum: ['critical', 'high', 'medium', 'low'],
    required: true,
  },
});

ComplianceRuleSchema.index({ framework: 1, rule_id: 1 }, { unique: true });

export const ComplianceRule = model<ComplianceRuleDocument>(
  'ComplianceRule',
  ComplianceRuleSchema,
);

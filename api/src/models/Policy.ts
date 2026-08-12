import { Schema, model, Document } from 'mongoose';
import { NormalizedRule, NormalizedRuleSchema } from './NormalizedRule';

export interface PolicyDocument extends Document {
  user_id: string;
  name: string;
  description: string;
  source_type: 'aws' | 'firewall' | 'iam';
  raw_content: string;
  normalized_rules: NormalizedRule[];
  tags: string[];
  created_at: Date;
  updated_at: Date;
}

const PolicySchema = new Schema<PolicyDocument>(
  {
    user_id: { type: String, required: true },
    name: { type: String, required: true },
    description: { type: String, default: '' },
    source_type: {
      type: String,
      enum: ['aws', 'firewall', 'iam'],
      required: true,
    },
    raw_content: { type: String, required: true },
    normalized_rules: { type: [NormalizedRuleSchema], default: [] },
    tags: { type: [String], default: [] },
  },
  { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } },
);

PolicySchema.index({ user_id: 1, created_at: -1 });

export const Policy = model<PolicyDocument>('Policy', PolicySchema);

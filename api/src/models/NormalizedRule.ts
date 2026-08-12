import { Schema } from 'mongoose';

export interface PortRange {
  start: number;
  end: number;
}

export interface Endpoint {
  type: 'cidr' | 'ip' | 'security_group' | 'principal';
  value: string;
}

export interface NormalizedRule {
  id: string;
  source_type: 'security_group' | 'firewall' | 'iam_policy';
  source_id: string;

  protocol: string;
  port_range: PortRange | null;
  direction: 'ingress' | 'egress';

  source: Endpoint;
  destination: Endpoint;

  created_at: Date;
  modified_at: Date;
  description: string;
  tags: Record<string, string>;
}

export interface RiskScore {
  overall: number;
  permissiveness: number;
  exposure: number;
  compliance_violations: number;
  unused: number;
}

const PortRangeSchema = new Schema<PortRange>(
  {
    start: { type: Number, required: true },
    end: { type: Number, required: true },
  },
  { _id: false },
);

const EndpointSchema = new Schema<Endpoint>(
  {
    type: {
      type: String,
      enum: ['cidr', 'ip', 'security_group', 'principal'],
      required: true,
    },
    value: { type: String, required: true },
  },
  { _id: false },
);

export const NormalizedRuleSchema = new Schema<NormalizedRule>(
  {
    id: { type: String, required: true },
    source_type: {
      type: String,
      enum: ['security_group', 'firewall', 'iam_policy'],
      required: true,
    },
    source_id: { type: String, required: true },

    protocol: { type: String, required: true },
    port_range: { type: PortRangeSchema, default: null },
    direction: { type: String, enum: ['ingress', 'egress'], required: true },

    source: { type: EndpointSchema, required: true },
    destination: { type: EndpointSchema, required: true },

    created_at: { type: Date, required: true },
    modified_at: { type: Date, required: true },
    description: { type: String, default: '' },
    tags: { type: Map, of: String, default: {} },
  },
  { _id: false },
);

export const RiskScoreSchema = new Schema<RiskScore>(
  {
    overall: { type: Number, min: 0, max: 100, required: true },
    permissiveness: { type: Number, min: 0, max: 100, required: true },
    exposure: { type: Number, min: 0, max: 100, required: true },
    compliance_violations: { type: Number, min: 0, max: 100, required: true },
    unused: { type: Number, min: 0, max: 100, required: true },
  },
  { _id: false },
);

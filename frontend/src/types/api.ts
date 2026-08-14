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
  action: 'allow' | 'deny';
  source: Endpoint;
  destination: Endpoint;
  created_at: string;
  modified_at: string;
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

export type FindingType = 'overly_permissive' | 'conflict' | 'orphaned' | 'compliance_violation';
export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface Finding {
  type: FindingType;
  severity: Severity;
  rule_id: string;
  description: string;
  recommendation: string;
}

export interface Policy {
  _id: string;
  user_id: string;
  name: string;
  description: string;
  source_type: 'aws' | 'firewall' | 'iam';
  normalized_rules: NormalizedRule[];
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface Analysis {
  _id: string;
  policy_id: string;
  risk_score: RiskScore;
  findings: Finding[];
  generated_at: string;
}

export interface Alert {
  id: string;
  type: string;
  timestamp: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  status: string;
  description: string;
  account_username?: string;
  account_department?: string;
}

export interface ScoreFactor {
  name: string;
  points: number;
  reason: string;
  evidence_ref?: string | null;
}

export interface RiskScore {
  score: number;
  verdict: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "BENIGN" | string;
  factors: ScoreFactor[];
  uncertainties: string[];
  capped: boolean;
}

export interface ThreatPath {
  alert: Record<string, any>;
  account: Record<string, any>;
  ip: Record<string, any>;
  indicator: Record<string, any>;
  ip_relationship: Record<string, any>;
  ioc_relationship: Record<string, any>;
  path_label?: string;
}

export interface RelatedAccount {
  account: {
    id: string;
    username: string;
    department?: string;
    [key: string]: any;
  };
  shared_entity: Record<string, any>;
  shared_entity_type: "IP" | "ThreatIndicator";
  connection_type: "DIRECT" | "INDIRECT";
}

export interface DeviceInfo {
  device: {
    id: string;
    hostname: string;
    criticality: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
    status: "HEALTHY" | "SUSPICIOUS" | "COMPROMISED" | "ISOLATED";
    [key: string]: any;
  };
  account: Record<string, any>;
  access_relationship: Record<string, any>;
  connected_ips: Array<{
    ip: Record<string, any>;
    connection_rel: Record<string, any>;
  }>;
}

export interface PreviousCase {
  investigation: {
    id: string;
    alert_id: string;
    risk_score: number;
    verdict: string;
    created_at: string;
    recommendation: string;
    summary: string;
  };
  evidence: Array<Record<string, any>>;
}

export interface GraphNodeData {
  id: string;
  label: "Alert" | "Account" | "Device" | "IP" | "ThreatIndicator" | string;
  type: string;
  data: Record<string, any>;
}

export interface GraphEdgeData {
  id: string;
  source: string;
  target: string;
  label: string;
  data?: Record<string, any>;
}

export interface VisualizationData {
  nodes: GraphNodeData[];
  edges: GraphEdgeData[];
}

export interface InvestigationResult {
  investigation_id: string;
  alert_id: string;
  verdict: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "BENIGN" | string;
  risk_score: RiskScore;
  summary: string;
  recommendation: string;
  findings: string[];
  uncertainties: string[];
  threat_paths: ThreatPath[];
  related_accounts: RelatedAccount[];
  devices: DeviceInfo[];
  previous_cases: PreviousCase[];
  visualization_data: VisualizationData;
  error?: string | null;
}

export interface GraphStats {
  node_counts: Record<string, number>;
  relationship_counts: Record<string, number>;
  total_nodes: number;
  total_relationships: number;
}

export interface Event {
  entity_id: string;
  entity_type: 'user' | 'service_account' | 'edge_device';
  timestamp: string;
  source_ip: string;
  geo_location: string;
  resource_accessed: string;
  auth_method: string;
  session_duration: number;
  command_sequence: string;
  device_fingerprint: string;
}

export interface FeatureAttributionItem {
  baseline: any;
  observed: any;
  delta: any;
  weight: number;
  score: number;
}

export interface FeatureAttribution {
  hour_deviation: FeatureAttributionItem;
  geo_deviation: FeatureAttributionItem;
  resource_novelty: FeatureAttributionItem;
  session_duration_z: FeatureAttributionItem;
  auth_method_change: FeatureAttributionItem;
  fingerprint_mismatch: FeatureAttributionItem;
  [key: string]: FeatureAttributionItem;
}

export interface CoLabel {
  attack_type: string;
  confidence: number;
}

export interface PhantomAction {
  timestamp: string;
  action_type: 'AUTH_ATTEMPT' | 'RESOURCE_PROBE' | 'PRIVILEGE_ESCALATION_ATTEMPT' | 'LATERAL_PROBE' | 'DATA_READ_ATTEMPT';
  details: Record<string, any>;
}

export interface PhantomSession {
  entity_id: string;
  source_ip: string;
  status: 'ACTIVE' | 'TERMINATED';
  activated_at: string;
  elapsed_seconds: number;
  n_actions: number;
  actions: PhantomAction[];
  timeout_seconds: number;
}

export interface PhantomSummary {
  entity_id: string;
  duration_seconds: number;
  n_actions: number;
  action_types: Record<string, number>;
  resources_probed: string[];
  activated_at: string;
  terminated_at: string;
  actions?: PhantomAction[];
}

export interface Alert {
  alert_id: string;
  timestamp: string;
  entity_id: string;
  entity_type: 'user' | 'service_account' | 'edge_device';
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  attack_type: string;
  confidence: number;
  explanation: string;
  explanation_summary: string;
  feature_attribution: FeatureAttribution;
  co_labels: CoLabel[];
  profile_bootstrap: boolean;
  phantom_session: PhantomSession | null;
  phantom_activated: boolean;
  event: Event;
}

export interface SystemStatus {
  total_events_processed: number;
  total_alerts: number;
  active_phantom_sessions: number;
  entities_monitored: number;
  health: 'NOMINAL' | 'DEGRADED' | 'OFFLINE';
}

export interface RagAnswer {
  question: string;
  answer: string;
  evidence: Record<string, unknown>[];
  pinecone_status: string;
  generated_at: string;
}

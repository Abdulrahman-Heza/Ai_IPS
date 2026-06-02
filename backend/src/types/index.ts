/**
 * Type definitions for the IPS System
 */

// User-related types
export type UserRole = 'admin' | 'analyst' | 'viewer';
export type UserStatus = 'active' | 'inactive' | 'suspended';

export interface User {
  id: number;
  email: string;
  password_hash: string;
  full_name: string;
  role: UserRole;
  status: UserStatus;
  created_at: Date;
  updated_at: Date;
  last_login?: Date;
  organization_id: number;
  two_factor_enabled: boolean;
}

export interface CreateUserInput {
  email: string;
  password: string;
  full_name: string;
  role?: UserRole;
  organization_id: number;
}

export interface AuthPayload {
  user_id: number;
  email: string;
  role: UserRole;
  org_id: number;
  iat: number;
  exp: number;
}

// Organization types
export interface Organization {
  id: number;
  name: string;
  description?: string;
  api_key: string;
  subscription_tier: string;
  created_at: Date;
  updated_at: Date;
}

// Network node types
export type NodeType = 'server' | 'workstation' | 'device' | 'gateway';
export type NodeStatus = 'online' | 'offline' | 'suspicious';

export interface NetworkNode {
  id: number;
  name: string;
  ip_address: string;
  mac_address?: string;
  node_type: NodeType;
  location?: string;
  status: NodeStatus;
  organization_id: number;
  created_at: Date;
  updated_at: Date;
  last_heartbeat?: Date;
}

// Firewall rule types
export type RuleAction = 'allow' | 'block' | 'alert';
export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'ALL';

export interface FirewallRule {
  id: number;
  rule_name: string;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol: Protocol;
  action: RuleAction;
  priority: number;
  is_active: boolean;
  created_by: number;
  created_at: Date;
  updated_at: Date;
  organization_id: number;
}

export interface CreateFirewallRuleInput {
  rule_name: string;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol: Protocol;
  action: RuleAction;
  priority?: number;
  is_active?: boolean;
}

// Blocked IP types
export type ThreatLevel = 'low' | 'medium' | 'high' | 'critical';

export interface BlockedIP {
  id: number;
  ip_address: string;
  reason?: string;
  threat_level: ThreatLevel;
  detected_attack_type?: string;
  blocked_at: Date;
  unblock_at?: Date;
  is_permanent: boolean;
  organization_id: number;
}

export interface BlockIPInput {
  ip_address: string;
  reason?: string;
  threat_level?: ThreatLevel;
  duration_hours?: number;
  is_permanent?: boolean;
}

// Alert types
export type AlertType = 'DDoS' | 'SQLInjection' | 'BruteForce' | 'Malware' | 'Anomaly';
export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface Alert {
  _id?: string;
  timestamp: Date;
  alert_type: AlertType;
  severity: AlertSeverity;
  source_ip: string;
  destination_ip: string;
  port?: number;
  protocol?: string;
  confidence: number;
  description: string;
  attack_details?: {
    packet_count?: number;
    bytes_transferred?: number;
    duration_seconds?: number;
    patterns_matched?: string[];
  };
  actions_taken: string[];
  model_version?: string;
  raw_features?: Record<string, any>;
  organization_id: number;
  acknowledged?: boolean;
  acknowledged_by?: number;
  acknowledged_at?: Date;
}

export interface CreateAlertInput {
  alert_type: AlertType;
  severity: AlertSeverity;
  source_ip: string;
  destination_ip: string;
  port?: number;
  protocol?: string;
  confidence: number;
  description: string;
  attack_details?: Alert['attack_details'];
  model_version?: string;
  raw_features?: Record<string, any>;
}

// System configuration types
export type ConfigDataType = 'string' | 'integer' | 'boolean' | 'json';

export interface SystemConfiguration {
  id: number;
  config_key: string;
  config_value: string;
  data_type: ConfigDataType;
  description?: string;
  created_at: Date;
  updated_at: Date;
  organization_id: number;
}

// AI Model types
export type ModelType = 'detection' | 'classification' | 'anomaly';
export type DeploymentStatus = 'training' | 'testing' | 'deployed' | 'deprecated';

export interface AIModel {
  id: number;
  model_name: string;
  model_version: string;
  model_type: ModelType;
  accuracy?: number;
  precision?: number;
  recall?: number;
  f1_score?: number;
  training_dataset?: string;
  deployment_status: DeploymentStatus;
  created_at: Date;
  updated_at: Date;
}

// Authentication types
export interface LoginRequest {
  email: string;
  password: string;
}

export interface AuthResponse {
  token: string;
  refresh_token: string;
  user: {
    id: number;
    email: string;
    full_name: string;
    role: UserRole;
    organization_id: number;
  };
  expires_in: number;
}

// API Response types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: any;
  };
  timestamp: string;
  path: string;
}

export interface PaginatedResponse<T> {
  total: number;
  limit: number;
  offset: number;
  data: T[];
}

// IPS Service types
export interface IPSStatus {
  status: 'active' | 'inactive';
  mode: 'aggressive' | 'balanced' | 'conservative';
  blocked_ips_count: number;
  active_rules_count: number;
  last_update: Date;
  detection_rate: number;
  false_positive_rate: number;
}

// Error types
export class AppError extends Error {
  constructor(
    public code: string,
    public statusCode: number,
    message: string,
    public details?: any
  ) {
    super(message);
    this.name = 'AppError';
  }
}

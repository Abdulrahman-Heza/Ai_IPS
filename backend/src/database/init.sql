-- IPS System - PostgreSQL Database Initialization Script

-- Create users table
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(255) NOT NULL,
  role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')) DEFAULT 'viewer',
  status VARCHAR(50) NOT NULL CHECK (status IN ('active', 'inactive', 'suspended')) DEFAULT 'active',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP WITH TIME ZONE,
  organization_id INTEGER,
  two_factor_enabled BOOLEAN DEFAULT false,
  two_factor_secret VARCHAR(255)
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_organization_id ON users(organization_id);

-- Create organizations table
CREATE TABLE IF NOT EXISTS organizations (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  api_key VARCHAR(255) UNIQUE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  subscription_tier VARCHAR(50) DEFAULT 'basic'
);

CREATE INDEX idx_organizations_api_key ON organizations(api_key);

-- Foreign key constraint
ALTER TABLE users ADD CONSTRAINT fk_users_organization
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;

-- Create network_nodes table
CREATE TABLE IF NOT EXISTS network_nodes (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  ip_address INET NOT NULL UNIQUE,
  mac_address MACADDR,
  node_type VARCHAR(50) NOT NULL CHECK (node_type IN ('server', 'workstation', 'device', 'gateway')) DEFAULT 'server',
  location VARCHAR(255),
  status VARCHAR(50) NOT NULL CHECK (status IN ('online', 'offline', 'suspicious')) DEFAULT 'online',
  organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  last_heartbeat TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_network_nodes_organization_id ON network_nodes(organization_id);
CREATE INDEX idx_network_nodes_ip_address ON network_nodes(ip_address);

-- Create firewall_rules table
CREATE TABLE IF NOT EXISTS firewall_rules (
  id SERIAL PRIMARY KEY,
  rule_name VARCHAR(255) NOT NULL,
  source_ip INET,
  destination_ip INET,
  source_port INTEGER,
  destination_port INTEGER,
  protocol VARCHAR(10) NOT NULL CHECK (protocol IN ('TCP', 'UDP', 'ICMP', 'ALL')) DEFAULT 'ALL',
  action VARCHAR(50) NOT NULL CHECK (action IN ('allow', 'block', 'alert')) DEFAULT 'block',
  priority INTEGER DEFAULT 100,
  is_active BOOLEAN DEFAULT true,
  created_by INTEGER REFERENCES users(id),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE INDEX idx_firewall_rules_organization_id ON firewall_rules(organization_id);
CREATE INDEX idx_firewall_rules_is_active ON firewall_rules(is_active);

-- Create blocked_ips table
CREATE TABLE IF NOT EXISTS blocked_ips (
  id SERIAL PRIMARY KEY,
  ip_address INET NOT NULL,
  reason VARCHAR(255),
  threat_level VARCHAR(20) NOT NULL CHECK (threat_level IN ('low', 'medium', 'high', 'critical')) DEFAULT 'high',
  detected_attack_type VARCHAR(100),
  blocked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  unblock_at TIMESTAMP WITH TIME ZONE,
  is_permanent BOOLEAN DEFAULT false,
  organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  UNIQUE(ip_address, organization_id)
);

CREATE INDEX idx_blocked_ips_organization_id ON blocked_ips(organization_id);
CREATE INDEX idx_blocked_ips_ip_address ON blocked_ips(ip_address);
CREATE INDEX idx_blocked_ips_unblock_at ON blocked_ips(unblock_at);

-- Create system_configurations table
CREATE TABLE IF NOT EXISTS system_configurations (
  id SERIAL PRIMARY KEY,
  config_key VARCHAR(255) NOT NULL,
  config_value TEXT NOT NULL,
  data_type VARCHAR(50) NOT NULL CHECK (data_type IN ('string', 'integer', 'boolean', 'json')) DEFAULT 'string',
  description TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  UNIQUE(config_key, organization_id)
);

CREATE INDEX idx_system_configurations_organization_id ON system_configurations(organization_id);

-- Create ai_models table
CREATE TABLE IF NOT EXISTS ai_models (
  id SERIAL PRIMARY KEY,
  model_name VARCHAR(255) NOT NULL,
  model_version VARCHAR(50) NOT NULL,
  model_type VARCHAR(50) NOT NULL CHECK (model_type IN ('detection', 'classification', 'anomaly')) DEFAULT 'detection',
  accuracy DECIMAL(5,2),
  precision DECIMAL(5,2),
  recall DECIMAL(5,2),
  f1_score DECIMAL(5,2),
  training_dataset VARCHAR(255),
  deployment_status VARCHAR(50) NOT NULL CHECK (deployment_status IN ('training', 'testing', 'deployed', 'deprecated')) DEFAULT 'testing',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(model_name, model_version)
);

CREATE INDEX idx_ai_models_deployment_status ON ai_models(deployment_status);

-- Create sessions table for WebSocket connections
CREATE TABLE IF NOT EXISTS sessions (
  id SERIAL PRIMARY KEY,
  session_id VARCHAR(255) UNIQUE NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  socket_id VARCHAR(255),
  connected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  disconnected_at TIMESTAMP WITH TIME ZONE,
  is_active BOOLEAN DEFAULT true,
  ip_address INET
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_session_id ON sessions(session_id);
CREATE INDEX idx_sessions_is_active ON sessions(is_active);

-- Create default organization
INSERT INTO organizations (name, description, subscription_tier)
VALUES ('Default Organization', 'Default organization for testing', 'premium')
ON CONFLICT DO NOTHING;

-- Create default admin user (password: Admin@123)
-- Note: In production, set a strong password
INSERT INTO users (email, password_hash, full_name, role, organization_id, status)
SELECT
  'admin@ips-system.local',
  '$2b$10$Z/EtHrPLhEBu3lYhH0D5/.5qr.h4B3tTJcM8K3K5K9E3E3E3E3E3E', -- bcrypt hash
  'System Administrator',
  'admin',
  id,
  'active'
FROM organizations
WHERE name = 'Default Organization'
ON CONFLICT DO NOTHING;

-- Grant permissions
GRANT CONNECT ON DATABASE ips_db TO ips_user;
GRANT USAGE ON SCHEMA public TO ips_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ips_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ips_user;

\echo 'PostgreSQL Database initialization completed successfully!'

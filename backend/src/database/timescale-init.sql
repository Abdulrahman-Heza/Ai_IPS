-- TimescaleDB Initialization Script for Time-Series Data

-- Create network_metrics hypertable
CREATE TABLE IF NOT EXISTS network_metrics (
  time TIMESTAMP NOT NULL,
  node_id INTEGER,
  metric_name VARCHAR(100),
  metric_value DECIMAL(10,2),
  unit VARCHAR(50),
  organization_id INTEGER
);

-- Convert to hypertable (TimescaleDB extension)
SELECT create_hypertable('network_metrics', 'time', if_not_exists => TRUE);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_network_metrics_org_time ON network_metrics (organization_id, time DESC);
CREATE INDEX IF NOT EXISTS idx_network_metrics_node_time ON network_metrics (node_id, time DESC);
CREATE INDEX IF NOT EXISTS idx_network_metrics_metric ON network_metrics (metric_name, time DESC);

-- Create retention policy (1 year)
SELECT add_retention_policy('network_metrics', INTERVAL '1 year', if_not_exists => true);

-- Create threat_events hypertable
CREATE TABLE IF NOT EXISTS threat_events (
  time TIMESTAMP NOT NULL,
  organization_id INTEGER,
  threat_id VARCHAR(255),
  attack_type VARCHAR(100),
  severity VARCHAR(20),
  source_ip INET,
  destination_ip INET,
  confidence DECIMAL(5,2),
  packets_count INTEGER,
  bytes_transferred INTEGER,
  model_version VARCHAR(50)
);

SELECT create_hypertable('threat_events', 'time', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_threat_events_org_time ON threat_events (organization_id, time DESC);
CREATE INDEX IF NOT EXISTS idx_threat_events_severity ON threat_events (severity, time DESC);
CREATE INDEX IF NOT EXISTS idx_threat_events_attack_type ON threat_events (attack_type, time DESC);
CREATE INDEX IF NOT EXISTS idx_threat_events_source_ip ON threat_events (source_ip, time DESC);

SELECT add_retention_policy('threat_events', INTERVAL '90 days', if_not_exists => true);

-- Create system_health hypertable
CREATE TABLE IF NOT EXISTS system_health (
  time TIMESTAMP NOT NULL,
  organization_id INTEGER,
  node_id INTEGER,
  cpu_usage DECIMAL(5,2),
  memory_usage DECIMAL(5,2),
  disk_usage DECIMAL(5,2),
  network_latency INTEGER,
  services_healthy INTEGER,
  services_total INTEGER,
  status VARCHAR(50)
);

SELECT create_hypertable('system_health', 'time', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_system_health_org_time ON system_health (organization_id, time DESC);
CREATE INDEX IF NOT EXISTS idx_system_health_node_time ON system_health (node_id, time DESC);

SELECT add_retention_policy('system_health', INTERVAL '30 days', if_not_exists => true);

-- Create inference_metrics hypertable for AI model performance tracking
CREATE TABLE IF NOT EXISTS inference_metrics (
  time TIMESTAMP NOT NULL,
  model_version VARCHAR(50),
  inference_time_ms DECIMAL(8,2),
  prediction_class VARCHAR(50),
  confidence DECIMAL(5,2),
  is_correct BOOLEAN,
  batch_size INTEGER
);

SELECT create_hypertable('inference_metrics', 'time', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_inference_metrics_model ON inference_metrics (model_version, time DESC);
CREATE INDEX IF NOT EXISTS idx_inference_metrics_class ON inference_metrics (prediction_class, time DESC);

SELECT add_retention_policy('inference_metrics', INTERVAL '90 days', if_not_exists => true);

-- Create traffic_stats hypertable
CREATE TABLE IF NOT EXISTS traffic_stats (
  time TIMESTAMP NOT NULL,
  organization_id INTEGER,
  packets_per_second BIGINT,
  bytes_per_second BIGINT,
  active_connections INTEGER,
  unique_source_ips INTEGER,
  unique_dest_ips INTEGER,
  protocol_distribution JSONB
);

SELECT create_hypertable('traffic_stats', 'time', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_traffic_stats_org_time ON traffic_stats (organization_id, time DESC);

SELECT add_retention_policy('traffic_stats', INTERVAL '7 days', if_not_exists => true);

-- Create IPS_actions hypertable
CREATE TABLE IF NOT EXISTS ips_actions (
  time TIMESTAMP NOT NULL,
  organization_id INTEGER,
  threat_id VARCHAR(255),
  action_type VARCHAR(100),
  target_ip INET,
  status VARCHAR(50),
  response_time_ms INTEGER
);

SELECT create_hypertable('ips_actions', 'time', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_ips_actions_org ON ips_actions (organization_id, time DESC);
CREATE INDEX IF NOT EXISTS idx_ips_actions_status ON ips_actions (status, time DESC);

SELECT add_retention_policy('ips_actions', INTERVAL '30 days', if_not_exists => true);

-- Enable compression for old data (> 1 hour old)
SELECT alter_job(get_reorder_job_for_hypertable('network_metrics'), schedule_interval => '1h');
SELECT alter_job(get_compress_job_for_hypertable('threat_events'), schedule_interval => '1h');

-- Create continuous aggregates for common queries
CREATE MATERIALIZED VIEW IF NOT EXISTS threat_events_1h AS
  SELECT
    time_bucket('1 hour', time) AS bucket,
    organization_id,
    attack_type,
    severity,
    COUNT(*) as event_count,
    AVG(confidence) as avg_confidence,
    MAX(confidence) as max_confidence
  FROM threat_events
  GROUP BY bucket, organization_id, attack_type, severity
  WITH DATA;

CREATE INDEX IF NOT EXISTS idx_threat_events_1h_bucket ON threat_events_1h (bucket DESC, organization_id);

-- Refresh policy for continuous aggregate
SELECT add_continuous_agg_policy('threat_events_1h',
  start_offset => INTERVAL '2 hours',
  end_offset => INTERVAL '1 hour',
  schedule_interval => INTERVAL '30 minutes');

\echo '✅ TimescaleDB initialization completed successfully!'
\echo 'Created hypertables: network_metrics, threat_events, system_health, inference_metrics, traffic_stats, ips_actions'

// MongoDB Initialization Script

db = db.getSiblingDB('ips_db');

// Create alerts collection with TTL index (90 days retention)
db.createCollection('alerts');
db.alerts.createIndex({ createdAt: 1 }, { expireAfterSeconds: 7776000 });
db.alerts.createIndex({ organizationId: 1, timestamp: -1 });
db.alerts.createIndex({ severity: 1, timestamp: -1 });
db.alerts.createIndex({ sourceIp: 1 });
db.alerts.createIndex({ alertType: 1 });

// Create network traffic logs collection with TTL index (30 days retention)
db.createCollection('networkTrafficLogs');
db.networkTrafficLogs.createIndex({ createdAt: 1 }, { expireAfterSeconds: 2592000 });
db.networkTrafficLogs.createIndex({ organizationId: 1, timestamp: -1 });
db.networkTrafficLogs.createIndex({ sourceIp: 1 });
db.networkTrafficLogs.createIndex({ destinationIp: 1 });

// Create system events collection with TTL index (60 days retention)
db.createCollection('systemEvents');
db.systemEvents.createIndex({ createdAt: 1 }, { expireAfterSeconds: 5184000 });
db.systemEvents.createIndex({ organizationId: 1, timestamp: -1 });
db.systemEvents.createIndex({ nodeId: 1 });
db.systemEvents.createIndex({ eventType: 1 });

// Create attack patterns collection (no TTL)
db.createCollection('attackPatterns');
db.attackPatterns.createIndex({ patternName: 1 }, { unique: true });
db.attackPatterns.createIndex({ enabled: 1 });
db.attackPatterns.createIndex({ affectedAttackTypes: 1 });

// Create audit logs collection with TTL index (1 year retention)
db.createCollection('auditLogs');
db.auditLogs.createIndex({ createdAt: 1 }, { expireAfterSeconds: 31536000 });
db.auditLogs.createIndex({ organizationId: 1, timestamp: -1 });
db.auditLogs.createIndex({ userId: 1 });
db.auditLogs.createIndex({ action: 1 });

// Create threat intelligence collection
db.createCollection('threatIntelligence');
db.threatIntelligence.createIndex({ organizationId: 1 });
db.threatIntelligence.createIndex({ timestamp: -1 });
db.threatIntelligence.createIndex({ sourceIp: 1 });
db.threatIntelligence.createIndex({ threatLevel: 1 });

// Create detection cache collection (24 hour TTL)
db.createCollection('detectionCache');
db.detectionCache.createIndex({ createdAt: 1 }, { expireAfterSeconds: 86400 });
db.detectionCache.createIndex({ flowHash: 1 }, { unique: true });

// Create repair history collection with TTL index (60 days)
db.createCollection('repairHistory');
db.repairHistory.createIndex({ createdAt: 1 }, { expireAfterSeconds: 5184000 });
db.repairHistory.createIndex({ organizationId: 1, timestamp: -1 });
db.repairHistory.createIndex({ status: 1 });

// Create notifications collection with TTL index (30 days)
db.createCollection('notifications');
db.notifications.createIndex({ createdAt: 1 }, { expireAfterSeconds: 2592000 });
db.notifications.createIndex({ userId: 1, read: 1 });
db.notifications.createIndex({ organizationId: 1 });

// Create default attack patterns
db.attackPatterns.insertMany([
  {
    patternName: 'SYN_FLOOD',
    description: 'Detects SYN flood attacks',
    patternRules: [
      {
        metric: 'packet_rate',
        operator: '>',
        threshold: 10000,
        windowSeconds: 60
      },
      {
        metric: 'syn_flag_percentage',
        operator: '>',
        threshold: 0.8
      }
    ],
    affectedAttackTypes: ['DDoS'],
    enabled: true,
    createdAt: new Date(),
    updatedAt: new Date()
  },
  {
    patternName: 'SQL_INJECTION',
    description: 'Detects SQL injection attempts',
    patternRules: [
      {
        metric: 'sql_keywords_count',
        operator: '>',
        threshold: 5
      },
      {
        metric: 'quote_percentage',
        operator: '>',
        threshold: 0.15
      }
    ],
    affectedAttackTypes: ['SQLInjection'],
    enabled: true,
    createdAt: new Date(),
    updatedAt: new Date()
  },
  {
    patternName: 'BRUTE_FORCE',
    description: 'Detects brute force attacks',
    patternRules: [
      {
        metric: 'failed_attempts',
        operator: '>',
        threshold: 10
      },
      {
        metric: 'attempt_frequency',
        operator: '>',
        threshold: 5
      }
    ],
    affectedAttackTypes: ['BruteForce'],
    enabled: true,
    createdAt: new Date(),
    updatedAt: new Date()
  }
]);

// Create indexes for performance
db.alerts.createIndex({ 'attackDetails.patterns_matched': 1 });
db.auditLogs.createIndex({ 'changeDetails': 'text' });

print('✅ MongoDB initialization completed successfully!');
print('Created collections: alerts, networkTrafficLogs, systemEvents, attackPatterns, auditLogs, etc.');

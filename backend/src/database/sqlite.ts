import sqlite3 from 'sqlite3';
import path from 'path';
import fs from 'fs';
import { logger } from '../utils/logger';

let db: sqlite3.Database;

export async function initializeSQLite(): Promise<sqlite3.Database> {
  return new Promise((resolve, reject) => {
    const dataDir = path.join(process.cwd(), 'data');

    // Create data directory if it doesn't exist
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    const dbPath = path.join(dataDir, 'ips.db');

    db = new sqlite3.Database(dbPath, async (err) => {
      if (err) {
        logger.error('Failed to initialize SQLite:', err);
        reject(err);
      } else {
        try {
          await createTables();
          logger.info(`SQLite database initialized at ${dbPath}`);
          resolve(db);
        } catch (error) {
          logger.error('Failed to create tables:', error);
          reject(error);
        }
      }
    });
  });
}

async function createTables(): Promise<void> {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      // Users table
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          full_name TEXT NOT NULL DEFAULT '',
          role TEXT DEFAULT 'analyst',
          status TEXT DEFAULT 'active',
          organization_id INTEGER NOT NULL DEFAULT 1,
          two_factor_enabled INTEGER DEFAULT 0,
          last_login DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Network nodes table
      db.run(`
        CREATE TABLE IF NOT EXISTS network_nodes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          ip_address TEXT UNIQUE NOT NULL,
          mac_address TEXT,
          node_type TEXT DEFAULT 'server',
          location TEXT,
          status TEXT DEFAULT 'offline',
          organization_id INTEGER NOT NULL DEFAULT 1,
          last_heartbeat DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Alerts table
      db.run(`
        CREATE TABLE IF NOT EXISTS alerts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          _id TEXT UNIQUE,
          organization_id INTEGER NOT NULL DEFAULT 1,
          alert_type TEXT NOT NULL,
          severity TEXT NOT NULL,
          source_ip TEXT,
          destination_ip TEXT,
          port INTEGER,
          protocol TEXT,
          confidence REAL DEFAULT 0,
          description TEXT,
          attack_details TEXT,
          actions_taken TEXT DEFAULT '[]',
          model_version TEXT,
          raw_features TEXT,
          acknowledged INTEGER DEFAULT 0,
          acknowledged_by INTEGER,
          acknowledged_at DATETIME,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Blocked IPs table
      db.run(`
        CREATE TABLE IF NOT EXISTS blocked_ips (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          organization_id INTEGER NOT NULL DEFAULT 1,
          ip_address TEXT NOT NULL,
          reason TEXT,
          threat_level TEXT DEFAULT 'high',
          detected_attack_type TEXT,
          blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          unblock_at DATETIME,
          is_permanent INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Firewall rules table
      db.run(`
        CREATE TABLE IF NOT EXISTS firewall_rules (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          rule_name TEXT NOT NULL,
          source_ip TEXT,
          destination_ip TEXT,
          source_port INTEGER,
          destination_port INTEGER,
          protocol TEXT DEFAULT 'ALL',
          action TEXT,
          priority INTEGER DEFAULT 100,
          is_active INTEGER DEFAULT 1,
          created_by INTEGER DEFAULT 0,
          organization_id INTEGER NOT NULL DEFAULT 1,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Threat detections table
      db.run(`
        CREATE TABLE IF NOT EXISTS threat_detections (
          id TEXT PRIMARY KEY,
          organization_id TEXT NOT NULL,
          threat_type TEXT NOT NULL,
          confidence REAL,
          source_ip TEXT,
          destination_ip TEXT,
          payload TEXT,
          action_taken TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // System configuration table
      db.run(`
        CREATE TABLE IF NOT EXISTS system_config (
          key TEXT PRIMARY KEY,
          value TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `, (err) => {
        if (err) {
          reject(err);
          return;
        }

        db.run(`
          CREATE TABLE IF NOT EXISTS system_configurations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            config_key TEXT NOT NULL,
            config_value TEXT,
            data_type TEXT DEFAULT 'string',
            description TEXT,
            organization_id INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (organization_id, config_key)
          )
        `, (configErr) => {
          if (configErr) reject(configErr);
          else resolve();
        });
      });
    });
  });
}

export function getDatabase(): sqlite3.Database {
  if (!db) {
    throw new Error('Database not initialized. Call initializeSQLite first.');
  }
  return db;
}

export function runQuery(query: string, params: any[] = []): Promise<void> {
  return new Promise((resolve, reject) => {
    db.run(query, params, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

export function getRow(query: string, params: any[] = []): Promise<any> {
  return new Promise((resolve, reject) => {
    db.get(query, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

export function getAllRows(query: string, params: any[] = []): Promise<any[]> {
  return new Promise((resolve, reject) => {
    db.all(query, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows || []);
    });
  });
}

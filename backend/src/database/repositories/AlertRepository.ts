import { getAllRows, getRow, runQuery } from '../sqlite';
import { Alert, CreateAlertInput, AlertType, AlertSeverity } from '../../types';
import { logger } from '../../utils/logger';

export class AlertRepository {
  private mapRow(row: any): Alert {
    return {
      _id: row._id || String(row.id),
      timestamp: row.timestamp ? new Date(row.timestamp) : new Date(row.created_at),
      alert_type: row.alert_type,
      severity: row.severity,
      source_ip: row.source_ip,
      destination_ip: row.destination_ip,
      port: row.port ?? undefined,
      protocol: row.protocol ?? undefined,
      confidence: row.confidence,
      description: row.description,
      attack_details: row.attack_details ? JSON.parse(row.attack_details) : undefined,
      actions_taken: row.actions_taken ? JSON.parse(row.actions_taken) : [],
      model_version: row.model_version ?? undefined,
      raw_features: row.raw_features ? JSON.parse(row.raw_features) : undefined,
      organization_id: row.organization_id,
      acknowledged: Boolean(row.acknowledged),
      acknowledged_by: row.acknowledged_by ?? undefined,
      acknowledged_at: row.acknowledged_at ? new Date(row.acknowledged_at) : undefined,
    };
  }

  async create(org_id: number, input: CreateAlertInput): Promise<Alert> {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    await runQuery(
      `INSERT INTO alerts
       (_id, organization_id, alert_type, severity, source_ip, destination_ip, port, protocol,
        confidence, description, attack_details, actions_taken, model_version, raw_features, acknowledged, timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)`,
      [
        id,
        org_id,
        input.alert_type,
        input.severity,
        input.source_ip,
        input.destination_ip,
        input.port || null,
        input.protocol || null,
        input.confidence,
        input.description,
        input.attack_details ? JSON.stringify(input.attack_details) : null,
        JSON.stringify([]),
        input.model_version || null,
        input.raw_features ? JSON.stringify(input.raw_features) : null,
      ]
    );

    logger.info(`Alert created: ${id} in org ${org_id}`);
    return (await this.findById(id))!;
  }

  async findById(id: string): Promise<Alert | null> {
    const row = await getRow('SELECT * FROM alerts WHERE _id = ? OR id = ?', [id, id]);
    return row ? this.mapRow(row) : null;
  }

  async findByOrganization(
    org_id: number,
    limit = 50,
    offset = 0,
    filters?: {
      severity?: AlertSeverity;
      alert_type?: AlertType;
      start_date?: Date;
      end_date?: Date;
    }
  ): Promise<Alert[]> {
    const where = ['organization_id = ?'];
    const params: any[] = [org_id];

    if (filters?.severity) {
      where.push('severity = ?');
      params.push(filters.severity);
    }
    if (filters?.alert_type) {
      where.push('alert_type = ?');
      params.push(filters.alert_type);
    }
    if (filters?.start_date) {
      where.push('timestamp >= ?');
      params.push(filters.start_date.toISOString());
    }
    if (filters?.end_date) {
      where.push('timestamp <= ?');
      params.push(filters.end_date.toISOString());
    }

    params.push(limit, offset);
    const rows = await getAllRows(
      `SELECT * FROM alerts WHERE ${where.join(' AND ')} ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
      params
    );
    return rows.map(row => this.mapRow(row));
  }

  async findBySeverity(org_id: number, severity: AlertSeverity): Promise<Alert[]> {
    const rows = await getAllRows(
      'SELECT * FROM alerts WHERE organization_id = ? AND severity = ? ORDER BY timestamp DESC',
      [org_id, severity]
    );
    return rows.map(row => this.mapRow(row));
  }

  async findByType(org_id: number, alert_type: AlertType): Promise<Alert[]> {
    const rows = await getAllRows(
      'SELECT * FROM alerts WHERE organization_id = ? AND alert_type = ? ORDER BY timestamp DESC',
      [org_id, alert_type]
    );
    return rows.map(row => this.mapRow(row));
  }

  async findBySourceIP(org_id: number, source_ip: string): Promise<Alert[]> {
    const rows = await getAllRows(
      'SELECT * FROM alerts WHERE organization_id = ? AND source_ip = ? ORDER BY timestamp DESC',
      [org_id, source_ip]
    );
    return rows.map(row => this.mapRow(row));
  }

  async findUnacknowledged(org_id: number): Promise<Alert[]> {
    const rows = await getAllRows(
      'SELECT * FROM alerts WHERE organization_id = ? AND acknowledged = 0 ORDER BY timestamp DESC',
      [org_id]
    );
    return rows.map(row => this.mapRow(row));
  }

  async acknowledge(id: string, user_id: number): Promise<Alert | null> {
    await runQuery(
      'UPDATE alerts SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = CURRENT_TIMESTAMP WHERE _id = ? OR id = ?',
      [user_id, id, id]
    );

    logger.info(`Alert acknowledged: ${id} by user ${user_id}`);
    return this.findById(id);
  }

  async addAction(id: string, action: string): Promise<void> {
    const alert = await this.findById(id);
    if (!alert) return;

    const actions = [...alert.actions_taken, action];
    await runQuery(
      'UPDATE alerts SET actions_taken = ? WHERE _id = ? OR id = ?',
      [JSON.stringify(actions), id, id]
    );
  }

  async getStats(org_id: number, hours = 24): Promise<{
    total: number;
    by_severity: Record<AlertSeverity, number>;
    by_type: Record<AlertType, number>;
  }> {
    const since = new Date(Date.now() - hours * 3600000).toISOString();
    const totalRow = await getRow(
      'SELECT COUNT(*) as count FROM alerts WHERE organization_id = ? AND timestamp >= ?',
      [org_id, since]
    );
    const total = totalRow?.count || 0;
    const bySeverity = await getAllRows(
      'SELECT severity as _id, COUNT(*) as count FROM alerts WHERE organization_id = ? AND timestamp >= ? GROUP BY severity',
      [org_id, since]
    );
    const byType = await getAllRows(
      'SELECT alert_type as _id, COUNT(*) as count FROM alerts WHERE organization_id = ? AND timestamp >= ? GROUP BY alert_type',
      [org_id, since]
    );

    const severityMap: Record<AlertSeverity, number> = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };

    bySeverity.forEach((item: any) => {
      severityMap[item._id as AlertSeverity] = item.count;
    });

    const typeMap: Record<AlertType, number> = {
      DDoS: 0,
      SQLInjection: 0,
      BruteForce: 0,
      Malware: 0,
      Anomaly: 0,
    };

    byType.forEach((item: any) => {
      typeMap[item._id as AlertType] = item.count;
    });

    return {
      total,
      by_severity: severityMap,
      by_type: typeMap,
    };
  }

  async count(org_id: number): Promise<number> {
    const row = await getRow('SELECT COUNT(*) as count FROM alerts WHERE organization_id = ?', [org_id]);
    return row?.count || 0;
  }

  async delete(id: string): Promise<boolean> {
    const existing = await this.findById(id);
    await runQuery('DELETE FROM alerts WHERE _id = ? OR id = ?', [id, id]);
    logger.info(`Alert deleted: ${id}`);
    return Boolean(existing);
  }
}

export const alertRepository = new AlertRepository();

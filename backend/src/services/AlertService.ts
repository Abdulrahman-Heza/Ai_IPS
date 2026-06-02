import { alertRepository } from '../database/repositories/AlertRepository';
import { ipsService } from './IPSService';
import {
  Alert,
  CreateAlertInput,
  AlertType,
  AlertSeverity,
  ThreatLevel,
  AppError,
} from '../types';
import { logger } from '../utils/logger';

export class AlertService {
  /**
   * Create a new alert (typically from AI service)
   */
  async createAlert(org_id: number, input: CreateAlertInput): Promise<Alert> {
    logger.info(`Creating alert: ${input.alert_type} from ${input.source_ip}`);

    // Create alert in database
    const alert = await alertRepository.create(org_id, input);

    // Take automated action based on threat level
    await this.handleThreatResponse(org_id, alert);

    return alert;
  }

  /**
   * Handle automated threat response
   */
  private async handleThreatResponse(org_id: number, alert: Alert): Promise<void> {
    try {
      // Determine threat level from severity
      const threatLevel = this.mapSeverityToThreatLevel(alert.severity);

      // For high and critical threats, automatically block IP
      if (['high', 'critical'].includes(alert.severity)) {
        logger.info(`Auto-blocking IP due to ${alert.severity} alert: ${alert.source_ip}`);

        await ipsService.respondToThreat(org_id, {
          source_ip: alert.source_ip,
          threat_level: threatLevel,
          alert_type: alert.alert_type,
        });

        await alertRepository.addAction(alert._id || '', 'IP_BLOCKED');
      }
    } catch (error) {
      logger.error(`Failed to handle threat response: ${error}`);
    }
  }

  /**
   * Map alert severity to threat level
   */
  private mapSeverityToThreatLevel(severity: AlertSeverity): ThreatLevel {
    const mapping: Record<AlertSeverity, ThreatLevel> = {
      low: 'low',
      medium: 'medium',
      high: 'high',
      critical: 'critical',
    };

    return mapping[severity];
  }

  /**
   * Get alerts by organization
   */
  async getAlerts(
    org_id: number,
    limit = 50,
    offset = 0,
    filters?: {
      severity?: AlertSeverity;
      alert_type?: AlertType;
      start_date?: Date;
      end_date?: Date;
    }
  ): Promise<{
    total: number;
    limit: number;
    offset: number;
    data: Alert[];
  }> {
    const data = await alertRepository.findByOrganization(org_id, limit, offset, filters);
    const total = await alertRepository.count(org_id);

    return {
      total,
      limit,
      offset,
      data,
    };
  }

  /**
   * Get alert details
   */
  async getAlertById(alert_id: string): Promise<Alert | null> {
    return await alertRepository.findById(alert_id);
  }

  /**
   * Get unacknowledged alerts
   */
  async getUnacknowledgedAlerts(org_id: number): Promise<Alert[]> {
    return await alertRepository.findUnacknowledged(org_id);
  }

  /**
   * Get alerts by severity
   */
  async getAlertsBySeverity(org_id: number, severity: AlertSeverity): Promise<Alert[]> {
    return await alertRepository.findBySeverity(org_id, severity);
  }

  /**
   * Get alerts by type
   */
  async getAlertsByType(org_id: number, alert_type: AlertType): Promise<Alert[]> {
    return await alertRepository.findByType(org_id, alert_type);
  }

  /**
   * Get alerts from source IP
   */
  async getAlertsBySourceIP(org_id: number, source_ip: string): Promise<Alert[]> {
    return await alertRepository.findBySourceIP(org_id, source_ip);
  }

  /**
   * Acknowledge an alert
   */
  async acknowledgeAlert(org_id: number, alert_id: string, user_id: number): Promise<Alert | null> {
    logger.info(`Acknowledging alert: ${alert_id}`);

    // Verify alert belongs to organization
    const alert = await alertRepository.findById(alert_id);
    if (!alert || alert.organization_id !== org_id) {
      throw new AppError(
        'ALERT_NOT_FOUND',
        404,
        'Alert not found'
      );
    }

    return await alertRepository.acknowledge(alert_id, user_id);
  }

  /**
   * Get alert statistics
   */
  async getStats(org_id: number, hours = 24): Promise<{
    total: number;
    by_severity: Record<AlertSeverity, number>;
    by_type: Record<AlertType, number>;
  }> {
    return await alertRepository.getStats(org_id, hours);
  }

  /**
   * Get recent critical alerts
   */
  async getRecentCriticalAlerts(org_id: number, hours = 24): Promise<Alert[]> {
    const since = new Date(Date.now() - hours * 3600000);
    const alerts = await alertRepository.findBySeverity(org_id, 'critical');

    return alerts.filter((alert) => alert.timestamp >= since);
  }

  /**
   * Export alerts to CSV format
   */
  async exportAlerts(org_id: number, format: 'csv' | 'json' = 'csv'): Promise<string> {
    const alerts = await alertRepository.findByOrganization(org_id, 10000, 0);

    if (format === 'json') {
      return JSON.stringify(alerts, null, 2);
    }

    // CSV format
    const headers = [
      'timestamp',
      'alert_type',
      'severity',
      'source_ip',
      'destination_ip',
      'port',
      'confidence',
      'description',
      'acknowledged',
    ];

    const rows = alerts.map((alert) => [
      alert.timestamp.toISOString(),
      alert.alert_type,
      alert.severity,
      alert.source_ip,
      alert.destination_ip,
      alert.port || '',
      alert.confidence,
      `"${alert.description.replace(/"/g, '""')}"`,
      alert.acknowledged ? 'Yes' : 'No',
    ]);

    const csv = [headers.join(','), ...rows.map((row) => row.join(','))].join('\n');

    return csv;
  }

  /**
   * Delete alert
   */
  async deleteAlert(org_id: number, alert_id: string): Promise<boolean> {
    logger.warn(`Deleting alert: ${alert_id}`);

    const alert = await alertRepository.findById(alert_id);
    if (!alert || alert.organization_id !== org_id) {
      throw new AppError(
        'ALERT_NOT_FOUND',
        404,
        'Alert not found'
      );
    }

    return await alertRepository.delete(alert_id);
  }

  /**
   * Calculate risk score based on alert properties
   */
  calculateRiskScore(alert: Alert): number {
    let score = 0;

    // Base score from confidence
    score += alert.confidence * 0.5;

    // Severity multiplier
    const severityMultiplier: Record<AlertSeverity, number> = {
      low: 1,
      medium: 2,
      high: 3,
      critical: 4,
    };
    score *= severityMultiplier[alert.severity];

    // Attack type multiplier
    const typeMultiplier: Record<AlertType, number> = {
      DDoS: 3,
      SQLInjection: 4,
      BruteForce: 2,
      Malware: 5,
      Anomaly: 1.5,
    };
    score *= typeMultiplier[alert.alert_type];

    return Math.min(100, Math.round(score));
  }
}

export const alertService = new AlertService();

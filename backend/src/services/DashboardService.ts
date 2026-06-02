import { alertService } from './AlertService';
import { ipsService } from './IPSService';
import { networkNodeService } from './NetworkNodeService';
import { alertRepository } from '../database/repositories/AlertRepository';
import { blockedIPRepository } from '../database/repositories/BlockedIPRepository';
import { networkNodeRepository } from '../database/repositories/NetworkNodeRepository';
import { firewallRuleRepository } from '../database/repositories/FirewallRuleRepository';
import { logger } from '../utils/logger';

export class DashboardService {
  /**
   * Get complete dashboard overview
   */
  async getOverview(org_id: number): Promise<{
    summary: {
      threats_24h: number;
      critical_alerts: number;
      blocked_ips: number;
      detection_accuracy: number;
      response_time_ms: number;
    };
    network: {
      nodes_online: number;
      nodes_total: number;
      health_percentage: number;
    };
    ips: {
      active_blocks: number;
      active_rules: number;
      detection_rate: number;
      false_positive_rate: number;
    };
    top_threats: Array<{ type: string; count: number; severity: string }>;
    recent_activities: Array<{
      timestamp: Date;
      type: string;
      description: string;
      severity: string;
    }>;
  }> {
    logger.debug(`Getting dashboard overview for org ${org_id}`);

    // Get threat statistics
    const threatStats = await alertRepository.getStats(org_id, 24);
    const criticalAlerts = threatStats.by_severity.critical || 0;

    // Get IPS status
    const ipsStatus = await ipsService.getStatus(org_id);

    // Get network health
    const networkHealth = await networkNodeService.getHealthSummary(org_id);

    // Get active blocks
    const activeBlocks = await blockedIPRepository.countActive(org_id);
    const activeRules = await firewallRuleRepository.countActive(org_id);

    // Build top threats
    const topThreats = this.buildTopThreats(threatStats);

    // Get recent activities
    const recentActivities = await this.getRecentActivities(org_id);

    return {
      summary: {
        threats_24h: threatStats.total || 0,
        critical_alerts: criticalAlerts,
        blocked_ips: activeBlocks,
        detection_accuracy: ipsStatus.detection_rate,
        response_time_ms: 45.3, // Placeholder
      },
      network: {
        nodes_online: networkHealth.online,
        nodes_total: networkHealth.total,
        health_percentage: networkHealth.health_percentage,
      },
      ips: {
        active_blocks: activeBlocks,
        active_rules: activeRules,
        detection_rate: ipsStatus.detection_rate,
        false_positive_rate: ipsStatus.false_positive_rate,
      },
      top_threats: topThreats,
      recent_activities: recentActivities,
    };
  }

  /**
   * Get threat timeline (hourly aggregation)
   */
  async getThreatTimeline(org_id: number, hours = 24): Promise<
    Array<{
      timestamp: Date;
      threat_count: number;
      by_severity: Record<string, number>;
    }>
  > {
    const timeline: Array<{
      timestamp: Date;
      threat_count: number;
      by_severity: Record<string, number>;
    }> = [];

    // Create hourly buckets
    for (let i = 0; i < hours; i++) {
      const startTime = new Date(Date.now() - (hours - i) * 3600000);
      const endTime = new Date(startTime.getTime() + 3600000);

      const alerts = await alertRepository.findByOrganization(org_id, 10000, 0, {
        start_date: startTime,
        end_date: endTime,
      });

      const severityCount = { low: 0, medium: 0, high: 0, critical: 0 };
      alerts.forEach((alert) => {
        severityCount[alert.severity]++;
      });

      timeline.push({
        timestamp: startTime,
        threat_count: alerts.length,
        by_severity: severityCount,
      });
    }

    return timeline;
  }

  /**
   * Get system metrics
   */
  async getMetrics(org_id: number): Promise<{
    cpu_usage: number;
    memory_usage: number;
    disk_usage: number;
    network_latency: number;
  }> {
    // In production, this would fetch from monitoring system (Prometheus, etc)
    // For now, return placeholder values
    return {
      cpu_usage: Math.random() * 60 + 20, // 20-80%
      memory_usage: Math.random() * 50 + 30, // 30-80%
      disk_usage: Math.random() * 40 + 40, // 40-80%
      network_latency: Math.random() * 50 + 10, // 10-60ms
    };
  }

  /**
   * Get alert statistics summary
   */
  async getAlertStats(org_id: number, hours = 24): Promise<{
    total: number;
    by_severity: Record<string, number>;
    by_type: Record<string, number>;
    acknowledged: number;
    unacknowledged: number;
  }> {
    const stats = await alertRepository.getStats(org_id, hours);
    const unacknowledged = (await alertRepository.findUnacknowledged(org_id)).length;
    const acknowledged = stats.total - unacknowledged;

    return {
      ...stats,
      acknowledged,
      unacknowledged,
    };
  }

  /**
   * Get security score (0-100)
   */
  async getSecurityScore(org_id: number): Promise<number> {
    const health = await networkNodeService.getHealthSummary(org_id);
    const ipsStatus = await ipsService.getStatus(org_id);

    // Calculate weighted security score
    const networkScore = health.health_percentage; // 0-100
    const detectionScore = ipsStatus.detection_rate; // 0-100
    const fpPenalty = ipsStatus.false_positive_rate * 100; // 0-100

    const score = (networkScore * 0.4 + detectionScore * 0.4 + (100 - fpPenalty) * 0.2);

    return Math.round(Math.max(0, Math.min(100, score)));
  }

  /**
   * Build top threats list
   */
  private buildTopThreats(stats: any): Array<{ type: string; count: number; severity: string }> {
    const threats: Array<{ type: string; count: number; severity: string }> = [];

    // Get counts from stats
    const typeEntries = Object.entries(stats.by_type || {});

    typeEntries
      .sort(([, a]: any, [, b]: any) => (b as number) - (a as number))
      .slice(0, 5)
      .forEach(([type, count]: any) => {
        threats.push({
          type,
          count,
          severity: this.getTypeSeverity(type),
        });
      });

    return threats;
  }

  /**
   * Get severity for attack type
   */
  private getTypeSeverity(type: string): string {
    const severities: Record<string, string> = {
      Malware: 'critical',
      DDoS: 'high',
      SQLInjection: 'high',
      BruteForce: 'medium',
      Anomaly: 'low',
    };
    return severities[type] || 'medium';
  }

  /**
   * Get recent activities (mix of different event types)
   */
  private async getRecentActivities(org_id: number): Promise<
    Array<{
      timestamp: Date;
      type: string;
      description: string;
      severity: string;
    }>
  > {
    const activities: Array<{
      timestamp: Date;
      type: string;
      description: string;
      severity: string;
    }> = [];

    // Get recent critical alerts
    const recentAlerts = await alertRepository.findBySeverity(org_id, 'critical');
    const latestAlerts = recentAlerts.slice(0, 5);

    latestAlerts.forEach((alert) => {
      activities.push({
        timestamp: alert.timestamp,
        type: 'Alert',
        description: `${alert.alert_type} from ${alert.source_ip}`,
        severity: alert.severity,
      });
    });

    // Sort by timestamp descending
    activities.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    return activities.slice(0, 10);
  }
}

export const dashboardService = new DashboardService();

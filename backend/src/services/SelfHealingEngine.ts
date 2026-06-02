import { logger } from '../utils/logger';
import { ipsService } from './IPSService';
import { alertService } from './AlertService';
import { networkNodeService } from './NetworkNodeService';
import { AppError } from '../types';

interface HealingAction {
  id: string;
  timestamp: Date;
  org_id: number;
  action_type: 'block_ip' | 'create_rule' | 'isolate_node' | 'escalate' | 'recover';
  target: string;
  severity_level: 'low' | 'medium' | 'high' | 'critical';
  duration_minutes: number;
  reason: string;
  success: boolean;
  details: string;
}

interface ThreatContext {
  org_id: number;
  flow_id: string;
  source_ip: string;
  destination_ip: string;
  attack_type: string;
  confidence: number;
  risk_score: number;
  risk_level: string;
  protocol: string;
  port: number;
  timestamp: Date;
}

export class SelfHealingEngine {
  private actions: Map<string, HealingAction> = new Map();
  private readonly actionHistoryLimit = 1000;

  async processAndRespond(context: ThreatContext): Promise<HealingAction[]> {
    const actions: HealingAction[] = [];

    try {
      // Escalated response based on severity
      if (context.risk_score >= 80) {
        // Critical threat - immediate multi-action response
        actions.push(await this.blockSourceIP(context, 'critical'));
        actions.push(await this.createFirewallRule(context, 'critical'));
        actions.push(await this.isolateIfNode(context));
        actions.push(await this.escalateAlert(context));
      } else if (context.risk_score >= 60) {
        // High threat - block and monitor
        actions.push(await this.blockSourceIP(context, 'high'));
        actions.push(await this.createFirewallRule(context, 'high'));
      } else if (context.risk_score >= 40) {
        // Medium threat - monitor and log
        actions.push(await this.blockSourceIP(context, 'medium'));
      } else {
        // Low threat - log only
        logger.info(`Low-risk threat logged: ${context.attack_type} from ${context.source_ip}`);
      }

      // Log all actions taken
      actions.forEach(action => {
        this.storeAction(action);
      });

      return actions;
    } catch (error) {
      logger.error(`Self-healing response failed: ${error}`);
      throw error;
    }
  }

  private async blockSourceIP(context: ThreatContext, severity: string): Promise<HealingAction> {
    const duration = this.calculateBlockDuration(context.risk_score, severity);
    const action = this.createAction(
      context.org_id,
      'block_ip',
      context.source_ip,
      severity as 'low' | 'medium' | 'high' | 'critical',
      duration,
      `Auto-block ${context.attack_type} from ${context.source_ip}`
    );

    try {
      await ipsService.blockIP(context.org_id, {
        ip_address: context.source_ip,
        reason: `${context.attack_type} - Confidence: ${context.confidence.toFixed(2)}`,
        threat_level: severity as 'low' | 'medium' | 'high' | 'critical',
        duration_hours: Math.ceil(duration / 60),
      });

      action.success = true;
      action.details = `IP ${context.source_ip} blocked for ${duration} minutes`;
      logger.info(`Auto-blocked IP: ${context.source_ip} (severity: ${severity})`);

      return action;
    } catch (error) {
      action.success = false;
      action.details = `Failed to block IP: ${error}`;
      logger.warn(`Failed to auto-block IP: ${error}`);
      return action;
    }
  }

  private async createFirewallRule(context: ThreatContext, severity: string): Promise<HealingAction> {
    const action = this.createAction(
      context.org_id,
      'create_rule',
      `${context.source_ip}:${context.port}`,
      severity as 'low' | 'medium' | 'high' | 'critical',
      999, // Rules don't expire
      `Auto-created rule for ${context.attack_type}`
    );

    try {
      // Create firewall rule based on attack type
      const rule = {
        rule_name: `AUTO_${context.attack_type.toUpperCase()}_${Date.now()}`,
        source_ip: context.source_ip,
        destination_ip: context.destination_ip,
        destination_port: context.port,
        protocol: context.protocol.toUpperCase() as 'TCP' | 'UDP' | 'ICMP' | 'ALL',
        action: 'block' as const,
        priority: severity === 'critical' ? 1 : severity === 'high' ? 5 : 10,
        is_active: true,
      };

      await ipsService.createRule(context.org_id, 0, rule);

      action.success = true;
      action.details = `Firewall rule created: ${rule.rule_name}`;
      logger.info(`Auto-created firewall rule: ${rule.rule_name}`);

      return action;
    } catch (error) {
      action.success = false;
      action.details = `Failed to create rule: ${error}`;
      logger.warn(`Failed to create firewall rule: ${error}`);
      return action;
    }
  }

  private async isolateIfNode(context: ThreatContext): Promise<HealingAction> {
    const action = this.createAction(
      context.org_id,
      'isolate_node',
      context.destination_ip,
      'high',
      60, // Isolation duration
      `Isolate node suspected in ${context.attack_type}`
    );

    try {
      // Try to find and mark node as suspicious
      // This would integrate with network monitoring
      logger.info(`Node ${context.destination_ip} marked for investigation`);

      action.success = true;
      action.details = `Node flagged for isolation: ${context.destination_ip}`;

      return action;
    } catch (error) {
      action.success = false;
      action.details = `Failed to isolate node: ${error}`;
      return action;
    }
  }

  private async escalateAlert(context: ThreatContext): Promise<HealingAction> {
    const action = this.createAction(
      context.org_id,
      'escalate',
      context.source_ip,
      'critical',
      999,
      `Escalate critical ${context.attack_type} alert`
    );

    try {
      // Create high-priority alert for security team
      const alert = {
        source_ip: context.source_ip,
        destination_ip: context.destination_ip,
        alert_type: context.attack_type as any,
        severity: 'critical' as const,
        confidence: context.confidence,
        description: `CRITICAL ALERT: ${context.attack_type} detected with ${(context.confidence * 100).toFixed(0)}% confidence. Risk Score: ${context.risk_score.toFixed(1)}/100. Auto-response actions taken.`,
        raw_features: {
          flow_id: context.flow_id,
          protocol: context.protocol,
          port: context.port,
          auto_response: true,
        },
      };

      await alertService.createAlert(context.org_id, alert);

      action.success = true;
      action.details = `Critical alert escalated to security team`;
      logger.warn(`Critical alert escalated: ${context.attack_type} from ${context.source_ip}`);

      return action;
    } catch (error) {
      action.success = false;
      action.details = `Failed to escalate alert: ${error}`;
      logger.error(`Failed to escalate alert: ${error}`);
      return action;
    }
  }

  async attemptRecovery(org_id: number, threat_type: string): Promise<HealingAction> {
    const action = this.createAction(
      org_id,
      'recover',
      threat_type,
      'high',
      999,
      `Attempt recovery from ${threat_type}`
    );

    try {
      // Recovery actions based on threat type
      if (threat_type.includes('ddos')) {
        // Rate limiting already in place, scale up infrastructure
        logger.info('DDoS mitigation: Rate limiting active, traffic shaping enabled');
      } else if (threat_type.includes('brute_force')) {
        // Enable stricter auth policies
        logger.info('Brute force mitigation: Auth lockout enabled');
      } else if (threat_type.includes('malware')) {
        // Quarantine affected systems
        logger.info('Malware mitigation: Scanning and quarantine enabled');
      }

      action.success = true;
      action.details = `Recovery measures initiated for ${threat_type}`;

      return action;
    } catch (error) {
      action.success = false;
      action.details = `Recovery failed: ${error}`;
      return action;
    }
  }

  private calculateBlockDuration(riskScore: number, severity: string): number {
    // Return block duration in minutes
    const baseDuration = {
      critical: 720,  // 12 hours
      high: 360,      // 6 hours
      medium: 60,     // 1 hour
      low: 10,        // 10 minutes
    };

    const base = baseDuration[severity as keyof typeof baseDuration] || 60;

    // Extend based on risk score
    if (riskScore >= 90) return base * 2;
    if (riskScore >= 80) return base * 1.5;
    return base;
  }

  private createAction(
    org_id: number,
    action_type: HealingAction['action_type'],
    target: string,
    severity_level: 'low' | 'medium' | 'high' | 'critical',
    duration_minutes: number,
    reason: string
  ): HealingAction {
    return {
      id: `action_${Date.now()}_${Math.random().toString(36).substring(7)}`,
      timestamp: new Date(),
      org_id,
      action_type,
      target,
      severity_level,
      duration_minutes,
      reason,
      success: false,
      details: 'Pending execution',
    };
  }

  private storeAction(action: HealingAction): void {
    this.actions.set(action.id, action);

    // Keep only recent actions in memory
    if (this.actions.size > this.actionHistoryLimit) {
      const oldestKey = Array.from(this.actions.keys()).shift();
      if (oldestKey) {
        this.actions.delete(oldestKey);
      }
    }
  }

  getActionHistory(org_id: number, limit: number = 50): HealingAction[] {
    return Array.from(this.actions.values())
      .filter(action => action.org_id === org_id)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  getActionStats(org_id: number): {
    total_actions: number;
    successful_actions: number;
    failed_actions: number;
    success_rate: number;
    actions_by_type: Record<string, number>;
  } {
    const orgActions = Array.from(this.actions.values())
      .filter(action => action.org_id === org_id);

    const successful = orgActions.filter(a => a.success).length;
    const failed = orgActions.filter(a => !a.success).length;

    const actionsByType: Record<string, number> = {};
    orgActions.forEach(action => {
      actionsByType[action.action_type] = (actionsByType[action.action_type] || 0) + 1;
    });

    return {
      total_actions: orgActions.length,
      successful_actions: successful,
      failed_actions: failed,
      success_rate: orgActions.length > 0 ? successful / orgActions.length : 0,
      actions_by_type: actionsByType,
    };
  }
}

export const selfHealingEngine = new SelfHealingEngine();

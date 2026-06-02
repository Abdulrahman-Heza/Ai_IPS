import { blockedIPRepository } from '../database/repositories/BlockedIPRepository';
import { firewallRuleRepository } from '../database/repositories/FirewallRuleRepository';
import { alertRepository } from '../database/repositories/AlertRepository';
import {
  BlockedIP,
  FirewallRule,
  BlockIPInput,
  CreateFirewallRuleInput,
  ThreatLevel,
  IPSStatus,
} from '../types';
import { logger } from '../utils/logger';

export class IPSService {
  /**
   * Block an IP address
   */
  async blockIP(org_id: number, input: BlockIPInput): Promise<BlockedIP> {
    logger.info(`Blocking IP: ${input.ip_address} in org ${org_id}`);

    // Check if already blocked
    const existing = await blockedIPRepository.findByIP(input.ip_address, org_id);
    if (existing) {
      logger.warn(`IP already blocked: ${input.ip_address}`);
      throw new Error('IP address is already blocked');
    }

    // Create block entry
    const blocked = await blockedIPRepository.create(org_id, input);

    // Auto-create firewall rule
    await this.createBlockingRule(org_id, input.ip_address, 0, 1); // user_id = 0 for system

    return blocked;
  }

  /**
   * Unblock an IP address
   */
  async unblockIP(org_id: number, ip: string, created_by: number): Promise<boolean> {
    logger.info(`Unblocking IP: ${ip} in org ${org_id}`);

    const result = await blockedIPRepository.unblockByIP(ip, org_id);

    if (result) {
      // Create allowlist rule
      await this.createAllowRule(org_id, ip, created_by);
    }

    return result;
  }

  /**
   * Get list of blocked IPs
   */
  async getBlockedIPs(org_id: number, limit = 50, offset = 0): Promise<{
    total: number;
    data: BlockedIP[];
  }> {
    const data = await blockedIPRepository.findAll(org_id, limit, offset);
    const total = await blockedIPRepository.count(org_id);

    return { total, data };
  }

  /**
   * Get active blocks only
   */
  async getActiveBlocks(org_id: number): Promise<BlockedIP[]> {
    return await blockedIPRepository.findActive(org_id);
  }

  /**
   * Auto-unblock expired IPs
   */
  async cleanupExpiredBlocks(org_id: number): Promise<number> {
    const expired = await blockedIPRepository.findExpired(org_id);
    let count = 0;

    for (const block of expired) {
      const success = await blockedIPRepository.unblock(block.id);
      if (success) count++;
    }

    if (count > 0) {
      logger.info(`Cleaned up ${count} expired IP blocks in org ${org_id}`);
    }

    return count;
  }

  /**
   * Create firewall rule to block IP
   */
  private async createBlockingRule(org_id: number, ip: string, created_by: number, priority = 50): Promise<FirewallRule> {
    const rule: CreateFirewallRuleInput = {
      rule_name: `Auto-Block: ${ip}`,
      source_ip: ip,
      protocol: 'ALL',
      action: 'block',
      priority,
    };

    return await firewallRuleRepository.create(org_id, created_by, rule);
  }

  /**
   * Create firewall rule to allow IP
   */
  private async createAllowRule(org_id: number, ip: string, created_by: number, priority = 10): Promise<FirewallRule> {
    const rule: CreateFirewallRuleInput = {
      rule_name: `Allow: ${ip}`,
      source_ip: ip,
      protocol: 'ALL',
      action: 'allow',
      priority,
    };

    return await firewallRuleRepository.create(org_id, created_by, rule);
  }

  /**
   * Create firewall rule
   */
  async createRule(org_id: number, created_by: number, input: CreateFirewallRuleInput): Promise<FirewallRule> {
    logger.info(`Creating firewall rule: ${input.rule_name} in org ${org_id}`);
    return await firewallRuleRepository.create(org_id, created_by, input);
  }

  /**
   * Get all firewall rules
   */
  async getFirewallRules(org_id: number, limit = 100, offset = 0): Promise<{
    total: number;
    data: FirewallRule[];
  }> {
    const data = await firewallRuleRepository.findAll(org_id, limit, offset);
    const total = await firewallRuleRepository.count(org_id);

    return { total, data };
  }

  /**
   * Get active firewall rules
   */
  async getActiveRules(org_id: number): Promise<FirewallRule[]> {
    return await firewallRuleRepository.findActive(org_id);
  }

  /**
   * Update firewall rule
   */
  async updateRule(org_id: number, rule_id: number, updates: Partial<CreateFirewallRuleInput>): Promise<FirewallRule | null> {
    const rule = await firewallRuleRepository.findById(rule_id);

    if (!rule || rule.organization_id !== org_id) {
      throw new Error('Firewall rule not found');
    }

    return await firewallRuleRepository.update(rule_id, updates);
  }

  /**
   * Toggle rule active status
   */
  async toggleRule(org_id: number, rule_id: number, is_active: boolean): Promise<void> {
    const rule = await firewallRuleRepository.findById(rule_id);

    if (!rule || rule.organization_id !== org_id) {
      throw new Error('Firewall rule not found');
    }

    await firewallRuleRepository.toggleActive(rule_id, is_active);
  }

  /**
   * Delete firewall rule
   */
  async deleteRule(org_id: number, rule_id: number): Promise<boolean> {
    const rule = await firewallRuleRepository.findById(rule_id);

    if (!rule || rule.organization_id !== org_id) {
      throw new Error('Firewall rule not found');
    }

    return await firewallRuleRepository.delete(rule_id);
  }

  /**
   * Delete all firewall rules for an organization
   */
  async deleteAllRules(org_id: number): Promise<number> {
    return await firewallRuleRepository.deleteAll(org_id);
  }

  /**
   * Delete a single blocked IP by id
   */
  async deleteBlockedIP(org_id: number, id: number): Promise<boolean> {
    return await blockedIPRepository.deleteById(id, org_id);
  }

  /**
   * Delete all blocked IPs for an organization
   */
  async deleteAllBlockedIPs(org_id: number): Promise<number> {
    return await blockedIPRepository.deleteAll(org_id);
  }

  /**
   * Get IPS system status
   */
  async getStatus(org_id: number): Promise<IPSStatus> {
    const blockedCount = await blockedIPRepository.countActive(org_id);
    const rulesCount = await firewallRuleRepository.countActive(org_id);

    const stats = await alertRepository.getStats(org_id);
    const totalAlerts = stats.total || 1; // Prevent division by zero

    // Simple metrics - in production, track these properly
    const detectionRate = Math.min(100, (stats.total / totalAlerts) * 100) || 0;
    const falsePositiveRate = 0.3; // Placeholder

    return {
      status: 'active',
      mode: 'balanced',
      blocked_ips_count: blockedCount,
      active_rules_count: rulesCount,
      last_update: new Date(),
      detection_rate: detectionRate,
      false_positive_rate: falsePositiveRate,
    };
  }

  /**
   * Apply graduated response to threat
   */
  async respondToThreat(
    org_id: number,
    threat: {
      source_ip: string;
      threat_level: ThreatLevel;
      alert_type: string;
    }
  ): Promise<void> {
    logger.info(`Responding to threat: ${threat.alert_type} from ${threat.source_ip}`);

    // Graduated response based on threat level
    const response: BlockIPInput = {
      ip_address: threat.source_ip,
      reason: `Auto-response to ${threat.alert_type}`,
      threat_level: threat.threat_level,
      duration_hours: this.getDurationByThreatLevel(threat.threat_level),
    };

    try {
      await this.blockIP(org_id, response);
      logger.info(`Threat response completed for ${threat.source_ip}`);
    } catch (error) {
      logger.error(`Failed to respond to threat: ${error}`);
    }
  }

  /**
   * Get block duration based on threat level
   */
  private getDurationByThreatLevel(level: ThreatLevel): number {
    const durations: Record<ThreatLevel, number> = {
      low: 1,        // 1 hour
      medium: 6,     // 6 hours
      high: 24,      // 24 hours
      critical: 72,  // 72 hours
    };

    return durations[level];
  }
}

export const ipsService = new IPSService();

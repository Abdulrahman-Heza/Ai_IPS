import { query } from '../postgres';
import { FirewallRule, CreateFirewallRuleInput } from '../../types';
import { logger } from '../../utils/logger';

export class FirewallRuleRepository {
  async create(org_id: number, created_by: number, input: CreateFirewallRuleInput): Promise<FirewallRule> {
    const result = await query<FirewallRule>(
      `INSERT INTO firewall_rules
       (rule_name, source_ip, destination_ip, source_port, destination_port, protocol, action, priority, is_active, created_by, organization_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING *`,
      [
        input.rule_name,
        input.source_ip || null,
        input.destination_ip || null,
        input.source_port || null,
        input.destination_port || null,
        input.protocol || 'ALL',
        input.action || 'block',
        input.priority || 100,
        input.is_active !== false,
        created_by,
        org_id,
      ]
    );

    logger.info(`Firewall rule created: ${input.rule_name} in org ${org_id}`);
    return result.rows[0];
  }

  async findById(id: number): Promise<FirewallRule | null> {
    const result = await query<FirewallRule>(
      'SELECT * FROM firewall_rules WHERE id = $1',
      [id]
    );
    return result.rows[0] || null;
  }

  async findAll(org_id: number, limit = 100, offset = 0): Promise<FirewallRule[]> {
    const result = await query<FirewallRule>(
      `SELECT * FROM firewall_rules
       WHERE organization_id = $1
       ORDER BY priority ASC, created_at DESC
       LIMIT $2 OFFSET $3`,
      [org_id, limit, offset]
    );
    return result.rows;
  }

  async findActive(org_id: number): Promise<FirewallRule[]> {
    const result = await query<FirewallRule>(
      `SELECT * FROM firewall_rules
       WHERE organization_id = $1 AND is_active = true
       ORDER BY priority ASC`,
      [org_id]
    );
    return result.rows;
  }

  async findByPort(org_id: number, port: number): Promise<FirewallRule[]> {
    const result = await query<FirewallRule>(
      `SELECT * FROM firewall_rules
       WHERE organization_id = $1
       AND (destination_port = $2 OR source_port = $2 OR destination_port IS NULL)
       AND is_active = true
       ORDER BY priority ASC`,
      [org_id, port]
    );
    return result.rows;
  }

  async findByIP(org_id: number, ip: string): Promise<FirewallRule[]> {
    const result = await query<FirewallRule>(
      `SELECT * FROM firewall_rules
       WHERE organization_id = $1
       AND (source_ip = $2 OR destination_ip = $2 OR source_ip IS NULL)
       AND is_active = true
       ORDER BY priority ASC`,
      [org_id, ip]
    );
    return result.rows;
  }

  async update(id: number, updates: Partial<CreateFirewallRuleInput>): Promise<FirewallRule | null> {
    const fields: string[] = [];
    const values: any[] = [];
    let paramCount = 1;

    Object.entries(updates).forEach(([key, value]) => {
      fields.push(`${key} = $${paramCount}`);
      values.push(value);
      paramCount++;
    });

    fields.push(`updated_at = NOW()`);
    values.push(id);

    const result = await query<FirewallRule>(
      `UPDATE firewall_rules SET ${fields.join(', ')} WHERE id = $${paramCount} RETURNING *`,
      values
    );

    logger.info(`Firewall rule updated: ${id}`);
    return result.rows[0] || null;
  }

  async toggleActive(id: number, is_active: boolean): Promise<void> {
    await query(
      'UPDATE firewall_rules SET is_active = $1, updated_at = NOW() WHERE id = $2',
      [is_active, id]
    );
    logger.info(`Firewall rule ${id} toggled: ${is_active}`);
  }

  async delete(id: number): Promise<boolean> {
    const result = await query(
      'DELETE FROM firewall_rules WHERE id = $1',
      [id]
    );
    logger.info(`Firewall rule deleted: ${id}`);
    return result.rowCount! > 0;
  }

  async deleteAll(org_id: number): Promise<number> {
    const countResult = await query<{ count: number }>(
      'SELECT COUNT(*) as count FROM firewall_rules WHERE organization_id = $1',
      [org_id]
    );
    const count = parseInt(countResult.rows[0]?.count?.toString() ?? '0');
    await query('DELETE FROM firewall_rules WHERE organization_id = $1', [org_id]);
    logger.info(`All firewall rules deleted for org ${org_id}: ${count} records`);
    return count;
  }

  async count(org_id: number): Promise<number> {
    const result = await query<{ count: number }>(
      'SELECT COUNT(*) as count FROM firewall_rules WHERE organization_id = $1',
      [org_id]
    );
    return parseInt(result.rows[0].count.toString());
  }

  async countActive(org_id: number): Promise<number> {
    const result = await query<{ count: number }>(
      'SELECT COUNT(*) as count FROM firewall_rules WHERE organization_id = $1 AND is_active = true',
      [org_id]
    );
    return parseInt(result.rows[0].count.toString());
  }
}

export const firewallRuleRepository = new FirewallRuleRepository();

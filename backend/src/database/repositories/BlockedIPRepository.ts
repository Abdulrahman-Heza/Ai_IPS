import { query } from '../postgres';
import { BlockedIP, BlockIPInput, ThreatLevel } from '../../types';
import { logger } from '../../utils/logger';

export class BlockedIPRepository {
  async create(org_id: number, input: BlockIPInput): Promise<BlockedIP> {
    const unblockAt = input.duration_hours
      ? new Date(Date.now() + input.duration_hours * 3600000)
      : null;

    const result = await query<BlockedIP>(
      `INSERT INTO blocked_ips (ip_address, reason, threat_level, detected_attack_type, unblock_at, is_permanent, organization_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [
        input.ip_address,
        input.reason || null,
        input.threat_level || 'high',
        null,
        unblockAt,
        input.is_permanent || false,
        org_id,
      ]
    );

    logger.info(`IP blocked: ${input.ip_address} in org ${org_id}`);
    return result.rows[0];
  }

  async findByIP(ip: string, org_id: number): Promise<BlockedIP | null> {
    const result = await query<BlockedIP>(
      'SELECT * FROM blocked_ips WHERE ip_address = $1 AND organization_id = $2',
      [ip, org_id]
    );
    return result.rows[0] || null;
  }

  async findAll(org_id: number, limit = 50, offset = 0): Promise<BlockedIP[]> {
    const result = await query<BlockedIP>(
      `SELECT * FROM blocked_ips
       WHERE organization_id = $1
       ORDER BY blocked_at DESC
       LIMIT $2 OFFSET $3`,
      [org_id, limit, offset]
    );
    return result.rows;
  }

  async findByThreatLevel(org_id: number, threat_level: ThreatLevel): Promise<BlockedIP[]> {
    const result = await query<BlockedIP>(
      `SELECT * FROM blocked_ips
       WHERE organization_id = $1 AND threat_level = $2
       ORDER BY blocked_at DESC`,
      [org_id, threat_level]
    );
    return result.rows;
  }

  async findActive(org_id: number): Promise<BlockedIP[]> {
    const result = await query<BlockedIP>(
      `SELECT * FROM blocked_ips
       WHERE organization_id = $1
       AND (is_permanent = true OR unblock_at IS NULL OR unblock_at > NOW())
       ORDER BY blocked_at DESC`,
      [org_id]
    );
    return result.rows;
  }

  async findExpired(org_id: number): Promise<BlockedIP[]> {
    const result = await query<BlockedIP>(
      `SELECT * FROM blocked_ips
       WHERE organization_id = $1
       AND is_permanent = false
       AND unblock_at IS NOT NULL
       AND unblock_at <= NOW()
       ORDER BY unblock_at DESC`,
      [org_id]
    );
    return result.rows;
  }

  async unblock(id: number): Promise<boolean> {
    const result = await query(
      'DELETE FROM blocked_ips WHERE id = $1',
      [id]
    );
    logger.info(`IP unblocked: ${id}`);
    return result.rowCount! > 0;
  }

  async unblockByIP(ip: string, org_id: number): Promise<boolean> {
    const result = await query(
      'DELETE FROM blocked_ips WHERE ip_address = $1 AND organization_id = $2',
      [ip, org_id]
    );
    logger.info(`IP unblocked: ${ip}`);
    return result.rowCount! > 0;
  }

  async updateThreatInfo(id: number, attack_type: string, threat_level: ThreatLevel): Promise<void> {
    await query(
      `UPDATE blocked_ips
       SET detected_attack_type = $1, threat_level = $2, updated_at = NOW()
       WHERE id = $3`,
      [attack_type, threat_level, id]
    );
  }

  async deleteById(id: number, org_id: number): Promise<boolean> {
    const result = await query(
      'DELETE FROM blocked_ips WHERE id = $1 AND organization_id = $2',
      [id, org_id]
    );
    logger.info(`Blocked IP deleted by id: ${id}`);
    return result.rowCount > 0;
  }

  async deleteAll(org_id: number): Promise<number> {
    const countResult = await query<{ count: number }>(
      'SELECT COUNT(*) as count FROM blocked_ips WHERE organization_id = $1',
      [org_id]
    );
    const count = parseInt(countResult.rows[0]?.count?.toString() ?? '0');
    await query('DELETE FROM blocked_ips WHERE organization_id = $1', [org_id]);
    logger.info(`All blocked IPs deleted for org ${org_id}: ${count} records`);
    return count;
  }

  async count(org_id: number): Promise<number> {
    const result = await query<{ count: number }>(
      'SELECT COUNT(*) as count FROM blocked_ips WHERE organization_id = $1',
      [org_id]
    );
    return parseInt(result.rows[0].count.toString());
  }

  async countActive(org_id: number): Promise<number> {
    const result = await query<{ count: number }>(
      `SELECT COUNT(*) as count FROM blocked_ips
       WHERE organization_id = $1
       AND (is_permanent = true OR unblock_at IS NULL OR unblock_at > NOW())`,
      [org_id]
    );
    return parseInt(result.rows[0].count.toString());
  }
}

export const blockedIPRepository = new BlockedIPRepository();

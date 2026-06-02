import { query } from '../postgres';
import { NetworkNode, NodeType, NodeStatus } from '../../types';
import { logger } from '../../utils/logger';

export class NetworkNodeRepository {
  async create(org_id: number, node: Omit<NetworkNode, 'id' | 'created_at' | 'updated_at'>): Promise<NetworkNode> {
    const result = await query<NetworkNode>(
      `INSERT INTO network_nodes (name, ip_address, mac_address, node_type, location, status, organization_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [
        node.name,
        node.ip_address,
        node.mac_address || null,
        node.node_type || 'server',
        node.location || null,
        'online',
        org_id,
      ]
    );

    logger.info(`Network node created: ${node.ip_address} in org ${org_id}`);
    return result.rows[0];
  }

  async findById(id: number): Promise<NetworkNode | null> {
    const result = await query<NetworkNode>(
      'SELECT * FROM network_nodes WHERE id = $1',
      [id]
    );
    return result.rows[0] || null;
  }

  async findByIP(ip: string, org_id: number): Promise<NetworkNode | null> {
    const result = await query<NetworkNode>(
      'SELECT * FROM network_nodes WHERE ip_address = $1 AND organization_id = $2',
      [ip, org_id]
    );
    return result.rows[0] || null;
  }

  async findAll(org_id: number, limit = 100, offset = 0): Promise<NetworkNode[]> {
    const result = await query<NetworkNode>(
      `SELECT * FROM network_nodes
       WHERE organization_id = $1
       ORDER BY name ASC
       LIMIT $2 OFFSET $3`,
      [org_id, limit, offset]
    );
    return result.rows;
  }

  async findByType(org_id: number, node_type: NodeType): Promise<NetworkNode[]> {
    const result = await query<NetworkNode>(
      `SELECT * FROM network_nodes
       WHERE organization_id = $1 AND node_type = $2
       ORDER BY name ASC`,
      [org_id, node_type]
    );
    return result.rows;
  }

  async findByStatus(org_id: number, status: NodeStatus): Promise<NetworkNode[]> {
    const result = await query<NetworkNode>(
      `SELECT * FROM network_nodes
       WHERE organization_id = $1 AND status = $2
       ORDER BY name ASC`,
      [org_id, status]
    );
    return result.rows;
  }

  async findOnline(org_id: number): Promise<NetworkNode[]> {
    return this.findByStatus(org_id, 'online');
  }

  async update(id: number, updates: Partial<NetworkNode>): Promise<NetworkNode | null> {
    const fields: string[] = [];
    const values: any[] = [];
    let paramCount = 1;

    Object.entries(updates).forEach(([key, value]) => {
      if (!['id', 'created_at'].includes(key)) {
        fields.push(`${key} = $${paramCount}`);
        values.push(value);
        paramCount++;
      }
    });

    if (fields.length === 0) {
      return this.findById(id);
    }

    fields.push(`updated_at = NOW()`);
    values.push(id);

    const result = await query<NetworkNode>(
      `UPDATE network_nodes SET ${fields.join(', ')} WHERE id = $${paramCount} RETURNING *`,
      values
    );

    logger.info(`Network node updated: ${id}`);
    return result.rows[0] || null;
  }

  async updateStatus(id: number, status: NodeStatus): Promise<void> {
    await query(
      `UPDATE network_nodes SET status = $1, last_heartbeat = NOW(), updated_at = NOW() WHERE id = $2`,
      [status, id]
    );
  }

  async updateHeartbeat(id: number): Promise<void> {
    await query(
      'UPDATE network_nodes SET last_heartbeat = NOW() WHERE id = $1',
      [id]
    );
  }

  async delete(id: number): Promise<boolean> {
    const result = await query(
      'DELETE FROM network_nodes WHERE id = $1',
      [id]
    );
    logger.info(`Network node deleted: ${id}`);
    return result.rowCount! > 0;
  }

  async count(org_id: number): Promise<number> {
    const result = await query<{ count: number }>(
      'SELECT COUNT(*) as count FROM network_nodes WHERE organization_id = $1',
      [org_id]
    );
    return parseInt(result.rows[0].count.toString());
  }

  async countByStatus(org_id: number, status: NodeStatus): Promise<number> {
    const result = await query<{ count: number }>(
      'SELECT COUNT(*) as count FROM network_nodes WHERE organization_id = $1 AND status = $2',
      [org_id, status]
    );
    return parseInt(result.rows[0].count.toString());
  }

  async getHealthStats(org_id: number): Promise<{
    total: number;
    online: number;
    offline: number;
    suspicious: number;
  }> {
    const total = await this.count(org_id);
    const online = await this.countByStatus(org_id, 'online');
    const offline = await this.countByStatus(org_id, 'offline');
    const suspicious = await this.countByStatus(org_id, 'suspicious');

    return { total, online, offline, suspicious };
  }
}

export const networkNodeRepository = new NetworkNodeRepository();

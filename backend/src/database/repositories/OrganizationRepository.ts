import { query } from '../postgres';
import { Organization } from '../../types';
import { logger } from '../../utils/logger';

export class OrganizationRepository {
  async create(org: Omit<Organization, 'id' | 'created_at' | 'updated_at'>): Promise<Organization> {
    const result = await query<Organization>(
      `INSERT INTO organizations (name, description, subscription_tier)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [org.name, org.description || null, 'basic']
    );

    logger.info(`Organization created: ${org.name}`);
    return result.rows[0];
  }

  async findById(id: number): Promise<Organization | null> {
    const result = await query<Organization>(
      'SELECT * FROM organizations WHERE id = $1',
      [id]
    );
    return result.rows[0] || null;
  }

  async findByApiKey(api_key: string): Promise<Organization | null> {
    const result = await query<Organization>(
      'SELECT * FROM organizations WHERE api_key = $1',
      [api_key]
    );
    return result.rows[0] || null;
  }

  async findAll(limit = 100, offset = 0): Promise<Organization[]> {
    const result = await query<Organization>(
      'SELECT * FROM organizations ORDER BY created_at DESC LIMIT $1 OFFSET $2',
      [limit, offset]
    );
    return result.rows;
  }

  async update(id: number, updates: Partial<Organization>): Promise<Organization | null> {
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

    const result = await query<Organization>(
      `UPDATE organizations SET ${fields.join(', ')} WHERE id = $${paramCount} RETURNING *`,
      values
    );

    logger.info(`Organization updated: ${id}`);
    return result.rows[0] || null;
  }

  async generateApiKey(id: number): Promise<string> {
    const apiKey = this.createApiKey();

    await query(
      'UPDATE organizations SET api_key = $1, updated_at = NOW() WHERE id = $2',
      [apiKey, id]
    );

    logger.info(`API key generated for organization: ${id}`);
    return apiKey;
  }

  async delete(id: number): Promise<boolean> {
    const result = await query(
      'DELETE FROM organizations WHERE id = $1',
      [id]
    );
    logger.warn(`Organization deleted: ${id}`);
    return result.rowCount! > 0;
  }

  async count(): Promise<number> {
    const result = await query<{ count: number }>(
      'SELECT COUNT(*) as count FROM organizations'
    );
    return parseInt(result.rows[0].count.toString());
  }

  private createApiKey(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let key = 'ips_';
    for (let i = 0; i < 32; i++) {
      key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return key;
  }
}

export const organizationRepository = new OrganizationRepository();

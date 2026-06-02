import { query } from '../postgres';
import { User, CreateUserInput } from '../../types';
import { logger } from '../../utils/logger';

export class UserRepository {
  async create(input: CreateUserInput & { password_hash: string }): Promise<User> {
    const result = await query<User>(
      `INSERT INTO users (email, password_hash, full_name, role, organization_id, status)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [input.email, input.password_hash, input.full_name, input.role || 'viewer', input.organization_id, 'active']
    );

    logger.info(`User created: ${input.email}`);
    return result.rows[0];
  }

  async findByEmail(email: string): Promise<User | null> {
    const result = await query<User>(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    return result.rows[0] || null;
  }

  async findById(id: number): Promise<User | null> {
    const result = await query<User>(
      'SELECT * FROM users WHERE id = $1',
      [id]
    );
    return result.rows[0] || null;
  }

  async findByIdAndOrg(id: number, org_id: number): Promise<User | null> {
    const result = await query<User>(
      'SELECT * FROM users WHERE id = $1 AND organization_id = $2',
      [id, org_id]
    );
    return result.rows[0] || null;
  }

  async findByOrganization(org_id: number, limit = 50, offset = 0): Promise<User[]> {
    const result = await query<User>(
      'SELECT * FROM users WHERE organization_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3',
      [org_id, limit, offset]
    );
    return result.rows;
  }

  async update(id: number, updates: Partial<User>): Promise<User | null> {
    const fields: string[] = [];
    const values: any[] = [];
    let paramCount = 1;

    Object.entries(updates).forEach(([key, value]) => {
      if (key !== 'id' && key !== 'created_at') {
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

    const result = await query<User>(
      `UPDATE users SET ${fields.join(', ')} WHERE id = $${paramCount} RETURNING *`,
      values
    );

    logger.info(`User updated: ${id}`);
    return result.rows[0] || null;
  }

  async updateLastLogin(id: number): Promise<void> {
    await query(
      'UPDATE users SET last_login = NOW() WHERE id = $1',
      [id]
    );
  }

  async delete(id: number): Promise<boolean> {
    const result = await query(
      'DELETE FROM users WHERE id = $1',
      [id]
    );
    logger.info(`User deleted: ${id}`);
    return result.rowCount! > 0;
  }

  async countByOrganization(org_id: number): Promise<number> {
    const result = await query<{ count: number }>(
      'SELECT COUNT(*) as count FROM users WHERE organization_id = $1',
      [org_id]
    );
    return parseInt(result.rows[0].count.toString());
  }
}

export const userRepository = new UserRepository();

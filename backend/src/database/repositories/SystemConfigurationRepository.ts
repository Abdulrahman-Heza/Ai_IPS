import { query } from '../postgres';
import { SystemConfiguration, ConfigDataType } from '../../types';
import { logger } from '../../utils/logger';

export class SystemConfigurationRepository {
  async set(org_id: number, key: string, value: any, data_type: ConfigDataType = 'string'): Promise<SystemConfiguration> {
    // Check if exists
    const existing = await this.get(org_id, key);

    if (existing) {
      return this.update(org_id, key, value);
    }

    const result = await query<SystemConfiguration>(
      `INSERT INTO system_configurations (config_key, config_value, data_type, organization_id)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [key, JSON.stringify(value), data_type, org_id]
    );

    logger.info(`Configuration set: ${key} in org ${org_id}`);
    return result.rows[0];
  }

  async get(org_id: number, key: string): Promise<SystemConfiguration | null> {
    const result = await query<SystemConfiguration>(
      `SELECT * FROM system_configurations
       WHERE organization_id = $1 AND config_key = $2`,
      [org_id, key]
    );

    if (result.rows.length === 0) {
      return null;
    }

    const config = result.rows[0];
    // Parse the value based on data type
    try {
      config.config_value = JSON.parse(config.config_value);
    } catch {
      // Keep as string if not JSON
    }

    return config;
  }

  async getAll(org_id: number): Promise<Record<string, any>> {
    const result = await query<SystemConfiguration>(
      `SELECT * FROM system_configurations
       WHERE organization_id = $1
       ORDER BY config_key ASC`,
      [org_id]
    );

    const config: Record<string, any> = {};

    result.rows.forEach((item) => {
      try {
        config[item.config_key] = JSON.parse(item.config_value);
      } catch {
        config[item.config_key] = item.config_value;
      }
    });

    return config;
  }

  async update(org_id: number, key: string, value: any): Promise<SystemConfiguration> {
    const result = await query<SystemConfiguration>(
      `UPDATE system_configurations
       SET config_value = $1, updated_at = NOW()
       WHERE organization_id = $2 AND config_key = $3
       RETURNING *`,
      [JSON.stringify(value), org_id, key]
    );

    logger.info(`Configuration updated: ${key} in org ${org_id}`);
    return result.rows[0];
  }

  async delete(org_id: number, key: string): Promise<boolean> {
    const result = await query(
      `DELETE FROM system_configurations
       WHERE organization_id = $1 AND config_key = $2`,
      [org_id, key]
    );

    logger.info(`Configuration deleted: ${key} in org ${org_id}`);
    return result.rowCount! > 0;
  }

  async getManyByPrefix(org_id: number, prefix: string): Promise<Record<string, any>> {
    const result = await query<SystemConfiguration>(
      `SELECT * FROM system_configurations
       WHERE organization_id = $1 AND config_key LIKE $2
       ORDER BY config_key ASC`,
      [org_id, `${prefix}%`]
    );

    const config: Record<string, any> = {};

    result.rows.forEach((item) => {
      try {
        config[item.config_key] = JSON.parse(item.config_value);
      } catch {
        config[item.config_key] = item.config_value;
      }
    });

    return config;
  }
}

export const systemConfigurationRepository = new SystemConfigurationRepository();

import { Router, Request, Response, NextFunction } from 'express';
import { systemConfigurationRepository } from '../database/repositories/SystemConfigurationRepository';
import { authMiddleware, requireAdmin, checkOrgAccess } from '../middleware/auth';
import { AppError } from '../types';

const router = Router();

// All config routes require authentication
router.use(authMiddleware);

/**
 * GET /system/config
 * Get all configuration values
 */
router.get('/', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const config = await systemConfigurationRepository.getAll(req.auth.org_id);

    res.json({
      success: true,
      data: config,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /system/config/:key
 * Get specific configuration value
 */
router.get('/:key', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { key } = req.params;
    const config = await systemConfigurationRepository.get(req.auth.org_id, key);

    if (!config) {
      throw new AppError(
        'CONFIG_NOT_FOUND',
        404,
        `Configuration key '${key}' not found`
      );
    }

    res.json({
      success: true,
      data: {
        key: config.config_key,
        value: config.config_value,
        type: config.data_type,
      },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /system/config
 * Set configuration value
 */
router.post('/', requireAdmin, checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { key, value, data_type } = req.body;

    if (!key || value === undefined) {
      throw new AppError('INVALID_INPUT', 400, 'Missing key or value');
    }

    const config = await systemConfigurationRepository.set(
      req.auth.org_id,
      key,
      value,
      data_type || 'string'
    );

    res.status(201).json({
      success: true,
      data: {
        key: config.config_key,
        value: config.config_value,
        type: config.data_type,
      },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PUT /system/config/:key
 * Update configuration value
 */
router.put('/:key', requireAdmin, checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { key } = req.params;
    const { value } = req.body;

    if (value === undefined) {
      throw new AppError('INVALID_INPUT', 400, 'Missing value');
    }

    const config = await systemConfigurationRepository.update(req.auth.org_id, key, value);

    res.json({
      success: true,
      data: {
        key: config.config_key,
        value: config.config_value,
        type: config.data_type,
      },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /system/config/:key
 * Delete configuration
 */
router.delete('/:key', requireAdmin, checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { key } = req.params;

    const success = await systemConfigurationRepository.delete(req.auth.org_id, key);

    if (!success) {
      throw new AppError('CONFIG_NOT_FOUND', 404, `Configuration key '${key}' not found`);
    }

    res.json({
      success: true,
      data: { message: `Configuration '${key}' deleted` },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /system/config/prefix/:prefix
 * Get all configs matching a prefix
 */
router.get('/prefix/:prefix', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { prefix } = req.params;
    const config = await systemConfigurationRepository.getManyByPrefix(req.auth.org_id, prefix);

    res.json({
      success: true,
      data: config,
      count: Object.keys(config).length,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

export default router;

import { Router, Request, Response, NextFunction } from 'express';
import { networkNodeService } from '../services/NetworkNodeService';
import { authMiddleware, checkOrgAccess } from '../middleware/auth';
import { AppError } from '../types';

const router = Router();

// All network routes require authentication
router.use(authMiddleware);

/**
 * GET /network/nodes
 * List all network nodes
 */
router.get('/nodes', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const limit = Math.min(parseInt(req.query.limit as string) || 100, 500);
    const offset = parseInt(req.query.offset as string) || 0;

    const result = await networkNodeService.listNodes(req.auth.org_id, limit, offset);

    res.json({
      success: true,
      data: result.data,
      total: result.total,
      limit,
      offset,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /network/nodes/health
 * Get network health summary
 */
router.get('/nodes/health/summary', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const health = await networkNodeService.getHealthSummary(req.auth.org_id);

    res.json({
      success: true,
      data: health,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /network/nodes/online
 * Get only online nodes
 */
router.get('/nodes/online/list', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const nodes = await networkNodeService.getOnlineNodes(req.auth.org_id);

    res.json({
      success: true,
      data: nodes,
      total: nodes.length,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /network/nodes/:node_id
 * Get node details
 */
router.get('/nodes/:node_id', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { node_id } = req.params;
    const node = await networkNodeService.getNode(req.auth.org_id, parseInt(node_id));

    res.json({
      success: true,
      data: node,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /network/nodes
 * Register a new network node
 */
router.post('/nodes', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { name, ip_address, mac_address, node_type, location } = req.body;

    if (!name || !ip_address) {
      throw new AppError('INVALID_INPUT', 400, 'Missing name or ip_address');
    }

    const node = await networkNodeService.registerNode(req.auth.org_id, {
      name,
      ip_address,
      mac_address,
      node_type: node_type || 'server',
      location,
      status: 'online',
      organization_id: req.auth.org_id,
    });

    res.status(201).json({
      success: true,
      data: node,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PUT /network/nodes/:node_id
 * Update node
 */
router.put('/nodes/:node_id', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { node_id } = req.params;
    const updates = req.body;

    const updated = await networkNodeService.updateNode(req.auth.org_id, parseInt(node_id), updates);

    if (!updated) {
      throw new AppError('NODE_NOT_FOUND', 404, 'Node not found');
    }

    res.json({
      success: true,
      data: updated,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /network/nodes/:node_id/heartbeat
 * Record node heartbeat
 */
router.post('/nodes/:node_id/heartbeat', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { node_id } = req.params;

    await networkNodeService.recordHeartbeat(req.auth.org_id, parseInt(node_id));

    res.json({
      success: true,
      data: { message: 'Heartbeat recorded' },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /network/nodes/:node_id
 * Delete node
 */
router.delete('/nodes/:node_id', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { node_id } = req.params;

    const success = await networkNodeService.deleteNode(req.auth.org_id, parseInt(node_id));

    if (!success) {
      throw new AppError('NODE_NOT_FOUND', 404, 'Node not found');
    }

    res.json({
      success: true,
      data: { message: 'Node deleted' },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

export default router;

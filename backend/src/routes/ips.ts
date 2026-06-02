import { Router, Request, Response, NextFunction } from 'express';
import { ipsService } from '../services/IPSService';
import { authMiddleware, requireAnalyst, checkOrgAccess } from '../middleware/auth';
import { AppError } from '../types';

const router = Router();

// All IPS routes require authentication
router.use(authMiddleware);

/**
 * GET /ips/status
 * Get IPS system status
 */
router.get('/status', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const status = await ipsService.getStatus(req.auth.org_id);

    res.json({
      success: true,
      data: status,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /ips/blocked-ips
 * Get list of blocked IPs
 */
router.get('/blocked-ips', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const limit = Math.min(parseInt(req.query.limit as string) || 50, 200);
    const offset = parseInt(req.query.offset as string) || 0;

    const result = await ipsService.getBlockedIPs(req.auth.org_id, limit, offset);

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
 * POST /ips/block-ip
 * Manually block an IP
 */
router.post('/block-ip', requireAnalyst, checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { ip_address, reason, threat_level, duration_hours, is_permanent } = req.body;

    if (!ip_address) {
      throw new AppError('INVALID_INPUT', 400, 'Missing ip_address');
    }

    const blocked = await ipsService.blockIP(req.auth.org_id, {
      ip_address,
      reason,
      threat_level: threat_level || 'high',
      duration_hours: duration_hours || 24,
      is_permanent: is_permanent || false,
    });

    res.status(201).json({
      success: true,
      data: blocked,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /ips/unblock-ip/:ip_address
 * Unblock an IP
 */
router.post('/unblock-ip/:ip_address', requireAnalyst, checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { ip_address } = req.params;

    const success = await ipsService.unblockIP(req.auth.org_id, ip_address, req.auth.user_id);

    if (!success) {
      throw new AppError('IP_NOT_BLOCKED', 404, `IP ${ip_address} is not blocked`);
    }

    res.json({
      success: true,
      data: {
        message: `IP ${ip_address} has been unblocked`,
        ip_address,
      },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /ips/firewall-rules
 * Get all firewall rules
 */
router.get('/firewall-rules', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const limit = Math.min(parseInt(req.query.limit as string) || 100, 500);
    const offset = parseInt(req.query.offset as string) || 0;

    const result = await ipsService.getFirewallRules(req.auth.org_id, limit, offset);

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
 * POST /ips/firewall-rules
 * Create new firewall rule
 */
router.post('/firewall-rules', requireAnalyst, checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { rule_name, source_ip, destination_ip, source_port, destination_port, protocol, action, priority, is_active } = req.body;

    if (!rule_name || !action) {
      throw new AppError('INVALID_INPUT', 400, 'Missing rule_name or action');
    }

    const rule = await ipsService.createRule(req.auth.org_id, req.auth.user_id, {
      rule_name,
      source_ip,
      destination_ip,
      source_port,
      destination_port,
      protocol: protocol || 'ALL',
      action,
      priority: priority || 100,
      is_active: is_active !== false,
    });

    res.status(201).json({
      success: true,
      data: rule,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PUT /ips/firewall-rules/:rule_id
 * Update firewall rule
 */
router.put('/firewall-rules/:rule_id', requireAnalyst, checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { rule_id } = req.params;
    const updates = req.body;

    const updated = await ipsService.updateRule(req.auth.org_id, parseInt(rule_id), updates);

    if (!updated) {
      throw new AppError('RULE_NOT_FOUND', 404, 'Firewall rule not found');
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
 * DELETE /ips/blocked-ips/:id
 * Delete a single blocked IP record by id
 */
router.delete('/blocked-ips/:id', requireAnalyst, checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    const id = parseInt(req.params.id);
    if (isNaN(id)) throw new AppError('INVALID_INPUT', 400, 'Invalid id');
    const success = await ipsService.deleteBlockedIP(req.auth.org_id, id);
    if (!success) throw new AppError('NOT_FOUND', 404, 'Blocked IP not found');
    res.json({ success: true, data: { message: 'Blocked IP deleted' }, timestamp: new Date().toISOString(), path: req.path });
  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /ips/blocked-ips
 * Delete ALL blocked IPs for the organization
 */
router.delete('/blocked-ips', requireAnalyst, checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    const count = await ipsService.deleteAllBlockedIPs(req.auth.org_id);
    res.json({ success: true, data: { message: `Deleted ${count} blocked IP records`, count }, timestamp: new Date().toISOString(), path: req.path });
  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /ips/firewall-rules
 * Delete ALL firewall rules for the organization
 */
router.delete('/firewall-rules', requireAnalyst, checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    const count = await ipsService.deleteAllRules(req.auth.org_id);
    res.json({ success: true, data: { message: `Deleted ${count} firewall rules`, count }, timestamp: new Date().toISOString(), path: req.path });
  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /ips/firewall-rules/:rule_id
 * Delete firewall rule
 */
router.delete('/firewall-rules/:rule_id', requireAnalyst, checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { rule_id } = req.params;

    const success = await ipsService.deleteRule(req.auth.org_id, parseInt(rule_id));

    if (!success) {
      throw new AppError('RULE_NOT_FOUND', 404, 'Firewall rule not found');
    }

    res.json({
      success: true,
      data: { message: 'Firewall rule deleted' },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

export default router;

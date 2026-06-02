import { Router, Request, Response, NextFunction } from 'express';
import { alertService } from '../services/AlertService';
import { authMiddleware, requireAnalyst, checkOrgAccess } from '../middleware/auth';
import { AppError, AlertSeverity, AlertType } from '../types';

const router = Router();

// All alert routes require authentication
router.use(authMiddleware);

/**
 * GET /alerts
 * Get alerts with filtering
 */
router.get('/', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const limit = Math.min(parseInt(req.query.limit as string) || 50, 200);
    const offset = parseInt(req.query.offset as string) || 0;
    const severity = req.query.severity as AlertSeverity | undefined;
    const alert_type = req.query.alert_type as AlertType | undefined;
    const start_date = req.query.start_date ? new Date(req.query.start_date as string) : undefined;
    const end_date = req.query.end_date ? new Date(req.query.end_date as string) : undefined;

    const result = await alertService.getAlerts(
      req.auth.org_id,
      limit,
      offset,
      {
        severity,
        alert_type,
        start_date,
        end_date,
      }
    );

    res.json({
      success: true,
      data: result.data,
      total: result.total,
      limit: result.limit,
      offset: result.offset,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /alerts/:alert_id
 * Get alert details
 */
router.get('/:alert_id', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { alert_id } = req.params;

    const alert = await alertService.getAlertById(alert_id);

    if (!alert) {
      throw new AppError('ALERT_NOT_FOUND', 404, 'Alert not found');
    }

    if (alert.organization_id !== req.auth?.org_id) {
      throw new AppError('FORBIDDEN', 403, 'You do not have access to this alert');
    }

    res.json({
      success: true,
      data: alert,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /alerts/:alert_id/acknowledge
 * Acknowledge an alert
 */
router.post('/:alert_id/acknowledge', requireAnalyst, checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { alert_id } = req.params;

    const updated = await alertService.acknowledgeAlert(req.auth.org_id, alert_id, req.auth.user_id);

    if (!updated) {
      throw new AppError('ALERT_NOT_FOUND', 404, 'Alert not found');
    }

    res.json({
      success: true,
      data: {
        message: 'Alert acknowledged',
        alert_id,
        acknowledged_by: req.auth.user_id,
        acknowledged_at: updated.acknowledged_at,
      },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /alerts/stats
 * Get alert statistics
 */
router.get('/stats/summary', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const hours = parseInt(req.query.hours as string) || 24;
    const stats = await alertService.getStats(req.auth.org_id, hours);

    res.json({
      success: true,
      data: {
        ...stats,
        time_period_hours: hours,
      },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /alerts/unacknowledged
 * Get unacknowledged alerts
 */
router.get('/unacknowledged/list', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const alerts = await alertService.getUnacknowledgedAlerts(req.auth.org_id);

    res.json({
      success: true,
      data: alerts,
      total: alerts.length,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /alerts/critical
 * Get critical alerts from last 24 hours
 */
router.get('/critical/recent', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const hours = parseInt(req.query.hours as string) || 24;
    const alerts = await alertService.getRecentCriticalAlerts(req.auth.org_id, hours);

    res.json({
      success: true,
      data: alerts,
      total: alerts.length,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /alerts/export
 * Export alerts
 */
router.get('/export/download', requireAnalyst, checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const format = (req.query.format as 'csv' | 'json') || 'csv';
    const data = await alertService.exportAlerts(req.auth.org_id, format);

    const contentType = format === 'csv' ? 'text/csv' : 'application/json';
    const filename = `alerts_${new Date().toISOString().split('T')[0]}.${format}`;

    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(data);
  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /alerts/:alert_id
 * Delete an alert
 */
router.delete('/:alert_id', requireAnalyst, checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { alert_id } = req.params;

    const success = await alertService.deleteAlert(req.auth.org_id, alert_id);

    if (!success) {
      throw new AppError('ALERT_NOT_FOUND', 404, 'Alert not found');
    }

    res.json({
      success: true,
      data: { message: 'Alert deleted' },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

export default router;

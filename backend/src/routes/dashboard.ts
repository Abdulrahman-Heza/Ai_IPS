import { Router, Request, Response, NextFunction } from 'express';
import { dashboardService } from '../services/DashboardService';
import { authMiddleware, checkOrgAccess } from '../middleware/auth';
import { AppError } from '../types';

const router = Router();

// All dashboard routes require authentication
router.use(authMiddleware);

/**
 * GET /dashboard/overview
 * Get complete dashboard overview
 */
router.get('/overview', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const overview = await dashboardService.getOverview(req.auth.org_id);

    res.json({
      success: true,
      data: overview,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /dashboard/timeline
 * Get threat timeline (hourly)
 */
router.get('/timeline', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const hours = parseInt(req.query.hours as string) || 24;
    const timeline = await dashboardService.getThreatTimeline(req.auth.org_id, hours);

    res.json({
      success: true,
      data: {
        timeline,
        hours,
        interval: '1h',
      },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /dashboard/metrics
 * Get system metrics
 */
router.get('/metrics', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const metrics = await dashboardService.getMetrics(req.auth.org_id);

    res.json({
      success: true,
      data: metrics,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /dashboard/alerts/stats
 * Get alert statistics
 */
router.get('/alerts/stats', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const hours = parseInt(req.query.hours as string) || 24;
    const stats = await dashboardService.getAlertStats(req.auth.org_id, hours);

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
 * GET /dashboard/security-score
 * Get security score (0-100)
 */
router.get('/security-score', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const score = await dashboardService.getSecurityScore(req.auth.org_id);

    res.json({
      success: true,
      data: {
        score,
        status: score >= 80 ? 'excellent' : score >= 60 ? 'good' : score >= 40 ? 'fair' : 'poor',
        timestamp: new Date().toISOString(),
      },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

export default router;

import { Router, Request, Response, NextFunction } from 'express';
import { threatProcessingService } from '../services/ThreatProcessingService';
import { driftDetectionService } from '../services/DriftDetectionService';
import { selfHealingEngine } from '../services/SelfHealingEngine';
import { aiInferenceService } from '../services/AIInferenceService';
import { authMiddleware, checkOrgAccess } from '../middleware/auth';
import { AppError } from '../types';

const router = Router();

// All threat routes require authentication
router.use(authMiddleware);

/**
 * POST /threats/process
 * Process network flow with AI inference and auto-response
 */
router.post('/process', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const {
      flow_id,
      source_ip,
      destination_ip,
      protocol,
      source_port,
      destination_port,
      duration,
      forward_bytes,
      backward_bytes,
      forward_packets,
      backward_packets,
      features,
    } = req.body;

    // Validate required fields
    if (!flow_id || !source_ip || !destination_ip || !features || features.length !== 50) {
      throw new AppError('INVALID_INPUT', 400, 'Missing or invalid required fields');
    }

    const threat = await threatProcessingService.processNetworkFlow(
      req.auth.org_id,
      {
        flow_id,
        source_ip,
        destination_ip,
        protocol: protocol || 'TCP',
        source_port: source_port || 0,
        destination_port: destination_port || 0,
        duration: duration || 0,
        forward_bytes: forward_bytes || 0,
        backward_bytes: backward_bytes || 0,
        forward_packets: forward_packets || 0,
        backward_packets: backward_packets || 0,
        timestamp: new Date(),
      },
      features
    );

    res.json({
      success: true,
      data: threat,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /threats/batch
 * Process multiple flows in batch
 */
router.post('/batch', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { flows, features_list } = req.body;

    if (!flows || !features_list || flows.length !== features_list.length) {
      throw new AppError('INVALID_INPUT', 400, 'Invalid batch format');
    }

    const threats = await threatProcessingService.processBatch(
      req.auth.org_id,
      flows,
      features_list
    );

    res.json({
      success: true,
      data: threats,
      total: threats.length,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /threats/stats
 * Get threat processing statistics
 */
router.get('/stats', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const stats = threatProcessingService.getStats();
    const aiStatus = await aiInferenceService.getStatus();
    const healingStats = selfHealingEngine.getActionStats(req.auth.org_id);

    res.json({
      success: true,
      data: {
        threat_processing: stats,
        ai_service: {
          status: aiStatus.status,
          models_loaded: aiStatus.models_loaded,
          total_requests: aiStatus.total_requests,
        },
        self_healing: healingStats,
      },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /threats/health
 * Check AI inference service health
 */
router.get('/health', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const isHealthy = await threatProcessingService.validateAIConnection();

    res.json({
      success: true,
      data: {
        ai_service: isHealthy ? 'healthy' : 'unhealthy',
        message: isHealthy ? 'AI inference service is operational' : 'AI inference service is down',
      },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /threats/drift/alerts
 * Get model drift detection alerts
 */
router.get('/drift/alerts', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const limit = parseInt(req.query.limit as string) || 10;
    const alerts = await driftDetectionService.getRecentAlerts(req.auth.org_id, limit);

    res.json({
      success: true,
      data: alerts,
      count: alerts.length,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /threats/drift/reset-baseline
 * Reset drift detection baseline
 */
router.post('/drift/reset-baseline', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    await driftDetectionService.resetBaseline(req.auth.org_id);

    res.json({
      success: true,
      data: { message: 'Drift detection baseline reset' },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /threats/actions
 * Get self-healing action history
 */
router.get('/actions', checkOrgAccess, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const limit = parseInt(req.query.limit as string) || 20;
    const actions = selfHealingEngine.getActionHistory(req.auth.org_id, limit);
    const stats = selfHealingEngine.getActionStats(req.auth.org_id);

    res.json({
      success: true,
      data: {
        recent_actions: actions,
        statistics: stats,
      },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

export default router;

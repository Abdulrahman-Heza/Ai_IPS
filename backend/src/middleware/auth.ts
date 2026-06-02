import { Request, Response, NextFunction } from 'express';
import { verifyToken, extractToken } from '../utils/auth';
import { AppError } from '../types';
import { logger } from '../utils/logger';

/**
 * Extend Express Request to include auth data
 */
declare global {
  namespace Express {
    interface Request {
      auth?: {
        user_id: number;
        email: string;
        role: string;
        org_id: number;
      };
    }
  }
}

/**
 * Middleware to verify JWT token
 */
export function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  try {
    const authHeader = req.get('Authorization');
    const token = extractToken(authHeader);

    if (!token) {
      throw new AppError(
        'MISSING_TOKEN',
        401,
        'Missing or invalid authorization token'
      );
    }

    const payload = verifyToken(token);
    if (!payload) {
      throw new AppError(
        'INVALID_TOKEN',
        401,
        'Invalid or expired token'
      );
    }

    req.auth = {
      user_id: payload.user_id,
      email: payload.email,
      role: payload.role,
      org_id: payload.org_id,
    };

    next();
  } catch (error) {
    logger.debug('Auth middleware error:', error);
    if (error instanceof AppError) {
      res.status(error.statusCode).json({
        error: true,
        code: error.code,
        message: error.message,
        timestamp: new Date().toISOString(),
        path: req.path,
      });
    } else {
      res.status(401).json({
        error: true,
        code: 'UNAUTHORIZED',
        message: 'Unauthorized access',
        timestamp: new Date().toISOString(),
        path: req.path,
      });
    }
  }
}

/**
 * Middleware to check role-based access control
 */
export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.auth) {
      res.status(401).json({
        error: true,
        code: 'UNAUTHORIZED',
        message: 'Authentication required',
        timestamp: new Date().toISOString(),
        path: req.path,
      });
      return;
    }

    if (!roles.includes(req.auth.role)) {
      logger.warn(`Unauthorized access attempt: user ${req.auth.user_id} with role ${req.auth.role}`);
      res.status(403).json({
        error: true,
        code: 'FORBIDDEN',
        message: `This action requires one of the following roles: ${roles.join(', ')}`,
        timestamp: new Date().toISOString(),
        path: req.path,
      });
      return;
    }

    next();
  };
}

/**
 * Middleware to require admin role
 */
export const requireAdmin = requireRole('admin');

/**
 * Middleware to require analyst or admin role
 */
export const requireAnalyst = requireRole('analyst', 'admin');

/**
 * Middleware to check organization access
 */
export function checkOrgAccess(req: Request, res: Response, next: NextFunction): void {
  if (!req.auth) {
    res.status(401).json({
      error: true,
      code: 'UNAUTHORIZED',
      message: 'Authentication required',
      timestamp: new Date().toISOString(),
      path: req.path,
    });
    return;
  }

  const orgId = req.query.org_id || req.body.org_id || req.auth.org_id;

  if (req.auth.org_id !== Number(orgId) && req.auth.role !== 'admin') {
    logger.warn(`Cross-org access attempt: user ${req.auth.user_id} accessing org ${orgId}`);
    res.status(403).json({
      error: true,
      code: 'FORBIDDEN',
      message: 'You do not have access to this organization',
      timestamp: new Date().toISOString(),
      path: req.path,
    });
    return;
  }

  next();
}

/**
 * Middleware to log authentication actions
 */
export function logAuthAction(action: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const originalJson = res.json.bind(res);

    res.json = function (body: any) {
      if (res.statusCode >= 200 && res.statusCode < 300) {
        logger.info(`Auth action: ${action} - User: ${req.auth?.user_id || 'anonymous'}`);
      } else {
        logger.warn(`Auth action failed: ${action} - Status: ${res.statusCode}`);
      }
      return originalJson(body);
    };

    next();
  };
}

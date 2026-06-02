import { Router, Request, Response, NextFunction } from 'express';
import { authService } from '../services/AuthService';
import { authMiddleware, logAuthAction } from '../middleware/auth';
import { AppError } from '../types';
import { logger } from '../utils/logger';

const router = Router();

/**
 * POST /auth/register
 * Register a new user
 */
router.post('/register', logAuthAction('register'), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password, full_name, organization_id } = req.body;

    // Validation
    if (!email || !password || !full_name || !organization_id) {
      throw new AppError(
        'INVALID_INPUT',
        400,
        'Missing required fields: email, password, full_name, organization_id'
      );
    }

    const user = await authService.register({
      email,
      password,
      full_name,
      organization_id,
      role: 'analyst', // Default role — gives access to all IPS features
    });

    res.status(201).json({
      success: true,
      data: {
        user_id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role,
      },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /auth/login
 * Login user and return JWT token
 */
router.post('/login', logAuthAction('login'), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      throw new AppError(
        'INVALID_INPUT',
        400,
        'Missing email or password'
      );
    }

    const authResponse = await authService.login(email, password);

    res.json({
      success: true,
      data: authResponse,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /auth/refresh
 * Refresh access token
 */
router.post('/refresh', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { refresh_token } = req.body;

    if (!refresh_token) {
      throw new AppError(
        'INVALID_INPUT',
        400,
        'Missing refresh_token'
      );
    }

    const result = await authService.refreshToken(refresh_token);

    res.json({
      success: true,
      data: result,
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /auth/profile
 * Get authenticated user's profile
 */
router.get('/profile', authMiddleware, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const user = await authService.getUserProfile(req.auth.user_id);

    if (!user) {
      throw new AppError('USER_NOT_FOUND', 404, 'User not found');
    }

    res.json({
      success: true,
      data: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role,
        organization_id: user.organization_id,
        last_login: user.last_login,
      },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PUT /auth/profile
 * Update authenticated user's profile
 */
router.put('/profile', authMiddleware, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { full_name } = req.body;

    if (!full_name) {
      throw new AppError('INVALID_INPUT', 400, 'Missing full_name');
    }

    const updated = await authService.updateProfile(req.auth.user_id, {
      full_name,
    } as any);

    res.json({
      success: true,
      data: {
        id: updated?.id,
        email: updated?.email,
        full_name: updated?.full_name,
      },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /auth/change-password
 * Change user password
 */
router.post('/change-password', authMiddleware, async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.auth) {
      throw new AppError('UNAUTHORIZED', 401, 'Not authenticated');
    }

    const { old_password, new_password } = req.body;

    if (!old_password || !new_password) {
      throw new AppError('INVALID_INPUT', 400, 'Missing old_password or new_password');
    }

    await authService.changePassword(req.auth.user_id, old_password, new_password);

    res.json({
      success: true,
      data: {
        message: 'Password changed successfully',
      },
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } catch (error) {
    next(error);
  }
});

export default router;

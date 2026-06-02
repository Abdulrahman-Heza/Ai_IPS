import { userRepository } from '../database/repositories/UserRepository';
import {
  hashPassword,
  comparePassword,
  generateToken,
  generateRefreshToken,
  verifyRefreshToken,
  validatePasswordStrength,
} from '../utils/auth';
import { User, CreateUserInput, AuthResponse, AppError } from '../types';
import { logger } from '../utils/logger';

export class AuthService {
  /**
   * Register a new user
   */
  async register(input: CreateUserInput): Promise<User> {
    logger.info(`Registering user: ${input.email}`);

    // Check if user exists
    const existing = await userRepository.findByEmail(input.email);
    if (existing) {
      throw new AppError(
        'USER_EXISTS',
        409,
        `User with email ${input.email} already exists`
      );
    }

    // Validate password strength
    const passwordValidation = validatePasswordStrength(input.password);
    if (!passwordValidation.valid) {
      throw new AppError(
        'WEAK_PASSWORD',
        400,
        'Password does not meet security requirements',
        passwordValidation.errors
      );
    }

    // Hash password
    const password_hash = await hashPassword(input.password);

    // Create user
    const user = await userRepository.create({
      ...input,
      password_hash,
    });

    logger.info(`User registered successfully: ${user.email}`);
    return user;
  }

  /**
   * Login user
   */
  async login(email: string, password: string): Promise<AuthResponse> {
    logger.info(`Login attempt: ${email}`);

    // Find user
    const user = await userRepository.findByEmail(email);
    if (!user) {
      logger.warn(`Login failed - user not found: ${email}`);
      throw new AppError(
        'INVALID_CREDENTIALS',
        401,
        'Invalid email or password'
      );
    }

    // Check if user is active
    if (user.status !== 'active') {
      logger.warn(`Login failed - inactive user: ${email}`);
      throw new AppError(
        'USER_INACTIVE',
        403,
        `User account is ${user.status}`
      );
    }

    // Verify password
    const isPasswordValid = await comparePassword(password, user.password_hash);
    if (!isPasswordValid) {
      logger.warn(`Login failed - invalid password: ${email}`);
      throw new AppError(
        'INVALID_CREDENTIALS',
        401,
        'Invalid email or password'
      );
    }

    // Update last login
    await userRepository.updateLastLogin(user.id);

    // Generate tokens
    const token = generateToken(user);
    const refresh_token = generateRefreshToken(user);

    logger.info(`User logged in: ${email}`);

    return {
      token,
      refresh_token,
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role,
        organization_id: user.organization_id,
      },
      expires_in: 7 * 24 * 60 * 60, // 7 days in seconds
    };
  }

  /**
   * Refresh access token
   */
  async refreshToken(refresh_token: string): Promise<{ token: string; expires_in: number }> {
    const payload = verifyRefreshToken(refresh_token);

    if (!payload) {
      throw new AppError(
        'INVALID_REFRESH_TOKEN',
        401,
        'Invalid or expired refresh token'
      );
    }

    // Get user
    const user = await userRepository.findById(payload.user_id);
    if (!user) {
      throw new AppError(
        'USER_NOT_FOUND',
        404,
        'User not found'
      );
    }

    // Generate new token
    const token = generateToken(user);

    logger.info(`Token refreshed for user: ${user.email}`);

    return {
      token,
      expires_in: 7 * 24 * 60 * 60,
    };
  }

  /**
   * Change user password
   */
  async changePassword(
    user_id: number,
    old_password: string,
    new_password: string
  ): Promise<void> {
    logger.info(`Password change attempt for user: ${user_id}`);

    // Get user
    const user = await userRepository.findById(user_id);
    if (!user) {
      throw new AppError(
        'USER_NOT_FOUND',
        404,
        'User not found'
      );
    }

    // Verify old password
    const isPasswordValid = await comparePassword(old_password, user.password_hash);
    if (!isPasswordValid) {
      logger.warn(`Password change failed - invalid old password: ${user.email}`);
      throw new AppError(
        'INVALID_PASSWORD',
        401,
        'Current password is incorrect'
      );
    }

    // Validate new password
    const passwordValidation = validatePasswordStrength(new_password);
    if (!passwordValidation.valid) {
      throw new AppError(
        'WEAK_PASSWORD',
        400,
        'New password does not meet security requirements',
        passwordValidation.errors
      );
    }

    // Hash new password
    const password_hash = await hashPassword(new_password);

    // Update user
    await userRepository.update(user_id, { password_hash } as any);

    logger.info(`Password changed for user: ${user.email}`);
  }

  /**
   * Get user profile
   */
  async getUserProfile(user_id: number): Promise<User | null> {
    return await userRepository.findById(user_id);
  }

  /**
   * Update user profile
   */
  async updateProfile(user_id: number, updates: Partial<User>): Promise<User | null> {
    logger.info(`Updating profile for user: ${user_id}`);

    // Prevent updating certain fields
    const allowedFields = ['full_name'];
    const filtered: any = {};

    allowedFields.forEach((field) => {
      if (field in updates) {
        filtered[field] = (updates as any)[field];
      }
    });

    return await userRepository.update(user_id, filtered);
  }

  /**
   * Suspend user account
   */
  async suspendUser(user_id: number): Promise<void> {
    logger.warn(`Suspending user: ${user_id}`);

    const user = await userRepository.findById(user_id);
    if (!user) {
      throw new AppError(
        'USER_NOT_FOUND',
        404,
        'User not found'
      );
    }

    await userRepository.update(user_id, { status: 'suspended' } as any);
  }

  /**
   * Activate user account
   */
  async activateUser(user_id: number): Promise<void> {
    logger.info(`Activating user: ${user_id}`);

    const user = await userRepository.findById(user_id);
    if (!user) {
      throw new AppError(
        'USER_NOT_FOUND',
        404,
        'User not found'
      );
    }

    await userRepository.update(user_id, { status: 'active' } as any);
  }
}

export const authService = new AuthService();

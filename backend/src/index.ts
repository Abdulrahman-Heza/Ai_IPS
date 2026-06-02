import express, { Express, Request, Response, NextFunction } from 'express';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import cors from 'cors';
import compression from 'compression';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { logger } from './utils/logger';
import { initializeSQLite } from './database/sqlite';
import { AppError } from './types';
import authRoutes from './routes/auth';
import ipsRoutes from './routes/ips';
import alertsRoutes from './routes/alerts';
import networkRoutes from './routes/network';
import dashboardRoutes from './routes/dashboard';
import configRoutes from './routes/config';
import threatRoutes from './routes/threats';
import { initializePredictionEvents } from './websocket/PredictionEvents';

// Load environment variables
dotenv.config();

function corsAllowedOrigins(): string | string[] {
  const raw =
    process.env.CORS_ORIGIN ||
    'http://localhost:3000,http://127.0.0.1:3000';
  const list = raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return list.length === 1 ? list[0] : list;
}

const corsOrigin = corsAllowedOrigins();

const app: Express = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: corsOrigin,
    methods: ['GET', 'POST'],
  },
});

const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Middleware
app.use(helmet());
app.use(compression());
app.use(cors({
  origin: corsOrigin,
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Rate limiting — generous limits for a real-time dashboard with multiple polled endpoints
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000,  // 1 minute window
  max: 500,                  // 500 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: true, code: 'RATE_LIMITED', message: 'Too many requests, please slow down.' },
});
app.use('/api/', limiter);

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: NODE_ENV,
  });
});

// API v1 base path logging
app.use('/api/v1', (req: Request, res: Response, next: NextFunction) => {
  logger.debug(`${req.method} ${req.path}`);
  next();
});

// System Status
app.get('/api/v1/status', (req: Request, res: Response) => {
  res.json({
    message: 'IPS System API - Phase 2 Core Features',
    version: '1.0.0',
    status: 'active',
    endpoints: {
      auth: '/api/v1/auth',
      ips: '/api/v1/ips',
      alerts: '/api/v1/alerts',
    },
  });
});

// API Routes
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/ips', ipsRoutes);
app.use('/api/v1/alerts', alertsRoutes);
app.use('/api/v1/network', networkRoutes);
app.use('/api/v1/dashboard', dashboardRoutes);
app.use('/api/v1/system/config', configRoutes);
app.use('/api/v1/threats', threatRoutes);

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({
    error: true,
    code: 'NOT_FOUND',
    message: 'Endpoint not found',
    path: req.path,
  });
});

// Error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  if (err instanceof AppError) {
    logger.warn(`App Error [${err.code}]: ${err.message}`);
    res.status(err.statusCode).json({
      error: true,
      code: err.code,
      message: err.message,
      ...(NODE_ENV === 'development' && err.details && { details: err.details }),
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  } else {
    logger.error('Unhandled error:', err);
    res.status(500).json({
      error: true,
      code: 'SERVER_ERROR',
      message: NODE_ENV === 'development' ? err.message : 'Internal server error',
      timestamp: new Date().toISOString(),
      path: req.path,
    });
  }
});

// WebSocket connection handling
io.on('connection', (socket) => {
  logger.info(`Client connected: ${socket.id}`);

  socket.on('join_org', (data) => {
    const orgId = data.org_id;
    socket.join(`org_${orgId}`);
    logger.info(`Client ${socket.id} joined organization ${orgId}`);
  });

  socket.on('disconnect', () => {
    logger.info(`Client disconnected: ${socket.id}`);
  });

  socket.on('error', (error) => {
    logger.error(`Socket error for ${socket.id}:`, error);
  });
});

// Initialize databases and start server
async function startServer() {
  try {
    logger.info('🚀 Starting IPS System Backend (Simplified - SQLite)...');
    logger.info(`Environment: ${NODE_ENV}`);

    // Initialize SQLite database
    logger.info('📦 Initializing SQLite database...');
    await initializeSQLite();
    logger.info('✅ SQLite initialized');

    // Initialize WebSocket event handlers
    logger.info('📡 Initializing WebSocket prediction events...');
    initializePredictionEvents(io);
    logger.info('✅ WebSocket events initialized');

    // Start server
    server.listen(PORT, () => {
      logger.info(`✅ Server running on port ${PORT}`);
      logger.info(`📊 WebSocket server active`);
      logger.info(`🔗 API available at http://localhost:${PORT}/api/v1`);
      logger.info('');
      logger.info('✅ IPS System - Simplified Edition');
      logger.info('');
      logger.info('Key Features:');
      logger.info('  🤖 AI Inference Service connected (localhost:5001)');
      logger.info('  ⚡ Real-time threat detection with WebSocket streaming');
      logger.info('  📊 SQLite database for simple student-friendly setup');
      logger.info('  🛡️ Automated IPS rules and IP blocking');
      logger.info('');
      logger.info('API Endpoints:');
      logger.info('  AUTH: register, login, refresh, profile, change-password');
      logger.info('  IPS: status, blocked-ips, block-ip, firewall-rules');
      logger.info('  ALERTS: list, details, acknowledge, stats, unacknowledged');
      logger.info('  NETWORK: nodes, health, online, register, heartbeat');
      logger.info('  DASHBOARD: overview, timeline, metrics, stats, security-score');
      logger.info('  CONFIG: get, set, update, delete');
      logger.info('  THREATS: process, batch, stats, health, drift, actions');
      logger.info('');
      logger.info('🚨 WebSocket Events:');
      logger.info('  subscribe_predictions: Real-time threat alerts');
      logger.info('  request_metrics: Live metrics stream');
      logger.info('  request_actions: Self-healing action tracking');
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      logger.info('SIGTERM received, shutting down gracefully...');
      server.close(() => {
        logger.info('Server closed');
        process.exit(0);
      });
    });

    process.on('SIGINT', () => {
      logger.info('SIGINT received, shutting down gracefully...');
      server.close(() => {
        logger.info('Server closed');
        process.exit(0);
      });
    });

  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

export { app, server, io };

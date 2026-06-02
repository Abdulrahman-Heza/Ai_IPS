import { Server as SocketIOServer, Socket } from 'socket.io';
import { logger } from '../utils/logger';
import { aiInferenceService } from '../services/AIInferenceService';
import { driftDetectionService } from '../services/DriftDetectionService';
import { selfHealingEngine } from '../services/SelfHealingEngine';
import { alertService } from '../services/AlertService';

interface RealTimeMetrics {
  timestamp: Date;
  total_flows: number;
  threats_detected: number;
  avg_confidence: number;
  avg_risk_score: number;
  high_risk_count: number;
  critical_count: number;
}

export class PredictionEventHandler {
  private io: SocketIOServer;
  private metricsBuffer: Map<number, RealTimeMetrics> = new Map();

  constructor(io: SocketIOServer) {
    this.io = io;
  }

  setupListeners(): void {
    this.io.on('connection', (socket: Socket) => {
      logger.info(`Prediction socket connected: ${socket.id}`);

      socket.on('subscribe_predictions', (data) => {
        this.handleSubscribePredictions(socket, data);
      });

      socket.on('request_metrics', (data) => {
        this.handleRequestMetrics(socket, data);
      });

      socket.on('request_actions', (data) => {
        this.handleRequestActions(socket, data);
      });

      socket.on('disconnect', () => {
        logger.info(`Prediction socket disconnected: ${socket.id}`);
      });
    });
  }

  private handleSubscribePredictions(socket: Socket, data: any): void {
    const orgId = data.org_id;

    if (!orgId) {
      socket.emit('error', { message: 'org_id required' });
      return;
    }

    socket.join(`predictions:org_${orgId}`);
    logger.info(`Client ${socket.id} subscribed to predictions for org ${orgId}`);

    socket.emit('subscribed', {
      status: 'ok',
      message: `Subscribed to organization ${orgId} predictions`,
    });
  }

  private handleRequestMetrics(socket: Socket, data: any): void {
    const orgId = data.org_id;

    if (!orgId) {
      socket.emit('error', { message: 'org_id required' });
      return;
    }

    const metrics = this.metricsBuffer.get(orgId) || {
      timestamp: new Date(),
      total_flows: 0,
      threats_detected: 0,
      avg_confidence: 0,
      avg_risk_score: 0,
      high_risk_count: 0,
      critical_count: 0,
    };

    socket.emit('metrics_update', {
      org_id: orgId,
      metrics,
    });
  }

  private handleRequestActions(socket: Socket, data: any): void {
    const orgId = data.org_id;

    if (!orgId) {
      socket.emit('error', { message: 'org_id required' });
      return;
    }

    const actions = selfHealingEngine.getActionHistory(orgId, data.limit || 10);
    const stats = selfHealingEngine.getActionStats(orgId);

    socket.emit('actions_update', {
      org_id: orgId,
      recent_actions: actions,
      statistics: stats,
    });
  }

  async broadcastPrediction(
    org_id: number,
    prediction: {
      flow_id: string;
      source_ip: string;
      destination_ip: string;
      attack_type: string;
      confidence: number;
      risk_score: number;
      risk_level: string;
      protocol: string;
      port: number;
      timestamp: Date;
    }
  ): Promise<void> {
    try {
      // Update metrics
      const metrics = this.metricsBuffer.get(org_id) || {
        timestamp: new Date(),
        total_flows: 0,
        threats_detected: 0,
        avg_confidence: 0.5,
        avg_risk_score: 0,
        high_risk_count: 0,
        critical_count: 0,
      };

      metrics.total_flows += 1;

      if (prediction.attack_type !== 'benign') {
        metrics.threats_detected += 1;
        metrics.avg_confidence = (metrics.avg_confidence + prediction.confidence) / 2;
        metrics.avg_risk_score = (metrics.avg_risk_score + prediction.risk_score) / 2;

        if (prediction.risk_score >= 60) {
          metrics.high_risk_count += 1;
        }
        if (prediction.risk_score >= 80) {
          metrics.critical_count += 1;
        }
      }

      this.metricsBuffer.set(org_id, metrics);

      // Broadcast to all clients subscribed to org predictions
      this.io.to(`predictions:org_${org_id}`).emit('prediction', {
        flow_id: prediction.flow_id,
        source_ip: prediction.source_ip,
        destination_ip: prediction.destination_ip,
        attack_type: prediction.attack_type,
        confidence: prediction.confidence,
        risk_score: prediction.risk_score,
        risk_level: prediction.risk_level,
        protocol: prediction.protocol,
        port: prediction.port,
        timestamp: prediction.timestamp,
      });

      // Broadcast metrics
      this.io.to(`predictions:org_${org_id}`).emit('metrics_update', {
        org_id,
        metrics,
      });

      // Log high-risk predictions
      if (prediction.risk_score >= 60) {
        logger.warn(
          `High-risk prediction: ${prediction.attack_type} from ${prediction.source_ip} ` +
          `(confidence: ${prediction.confidence.toFixed(2)}, risk: ${prediction.risk_score.toFixed(1)})`
        );
      }
    } catch (error) {
      logger.error(`Failed to broadcast prediction: ${error}`);
    }
  }

  async broadcastAction(org_id: number, action: any): Promise<void> {
    try {
      this.io.to(`predictions:org_${org_id}`).emit('action_taken', {
        org_id,
        action,
      });
    } catch (error) {
      logger.error(`Failed to broadcast action: ${error}`);
    }
  }

  async broadcastAlert(org_id: number, alert: any): Promise<void> {
    try {
      this.io.to(`predictions:org_${org_id}`).emit('alert', {
        org_id,
        alert,
      });
    } catch (error) {
      logger.error(`Failed to broadcast alert: ${error}`);
    }
  }

  getConnectedOrgs(): Set<number> {
    const orgs = new Set<number>();

    this.metricsBuffer.forEach((_, orgId) => {
      orgs.add(orgId);
    });

    return orgs;
  }

  clearMetrics(org_id?: number): void {
    if (org_id) {
      this.metricsBuffer.delete(org_id);
    } else {
      this.metricsBuffer.clear();
    }
  }
}

export let predictionEventHandler: PredictionEventHandler;

export function initializePredictionEvents(io: SocketIOServer): void {
  predictionEventHandler = new PredictionEventHandler(io);
  predictionEventHandler.setupListeners();
  logger.info('Prediction event handlers initialized');
}

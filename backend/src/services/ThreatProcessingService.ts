import { logger } from '../utils/logger';
import { aiInferenceService } from './AIInferenceService';
import { driftDetectionService } from './DriftDetectionService';
import { selfHealingEngine } from './SelfHealingEngine';
import { predictionEventHandler } from '../websocket/PredictionEvents';
import { alertService } from './AlertService';
import { AppError } from '../types';

interface NetworkFlow {
  flow_id: string;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  source_port: number;
  destination_port: number;
  duration: number;
  forward_bytes: number;
  backward_bytes: number;
  forward_packets: number;
  backward_packets: number;
  timestamp: Date;
}

interface ProcessedThreat {
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
  auto_response: string[];
}

export class ThreatProcessingService {
  private processedCount = 0;
  private threatCount = 0;
  private errorCount = 0;

  async processNetworkFlow(
    org_id: number,
    flow: NetworkFlow,
    features: number[]
  ): Promise<ProcessedThreat | null> {
    try {
      // Validate inputs
      if (features.length !== 50) {
        throw new AppError(
          'INVALID_FEATURES',
          400,
          `Expected 50 features, got ${features.length}`
        );
      }

      this.processedCount++;

      // Get AI prediction
      const prediction = await aiInferenceService.predict(
        features,
        flow.flow_id,
        {
          source_ip: flow.source_ip,
          destination_ip: flow.destination_ip,
          protocol: flow.protocol,
          timestamp: flow.timestamp.toISOString(),
        }
      );

      // Map AI response to threat
      const threat: ProcessedThreat = {
        flow_id: flow.flow_id,
        source_ip: flow.source_ip,
        destination_ip: flow.destination_ip,
        attack_type: prediction.ensemble_prediction.attack_type,
        confidence: prediction.ensemble_prediction.confidence,
        risk_score: prediction.risk_score,
        risk_level: prediction.risk_level,
        protocol: flow.protocol,
        port: flow.destination_port,
        timestamp: new Date(prediction.timestamp),
        auto_response: [],
      };

      // Record prediction for drift detection
      await driftDetectionService.recordPrediction(
        {
          attack_type: threat.attack_type,
          confidence: threat.confidence,
          risk_score: threat.risk_score,
          risk_level: threat.risk_level,
        },
        org_id
      );

      // Handle threats (non-benign)
      if (threat.attack_type !== 'benign') {
        this.threatCount++;

        // Execute self-healing response
        const actions = await selfHealingEngine.processAndRespond({
          org_id,
          flow_id: flow.flow_id,
          source_ip: flow.source_ip,
          destination_ip: flow.destination_ip,
          attack_type: threat.attack_type,
          confidence: threat.confidence,
          risk_score: threat.risk_score,
          risk_level: threat.risk_level,
          protocol: flow.protocol,
          port: flow.destination_port,
          timestamp: new Date(),
        });

        threat.auto_response = actions
          .filter(a => a.success)
          .map(a => `${a.action_type}: ${a.target}`);

        // Broadcast to dashboard
        if (predictionEventHandler) {
          await predictionEventHandler.broadcastPrediction(org_id, threat);

          for (const action of actions) {
            await predictionEventHandler.broadcastAction(org_id, action);
          }
        }

        logger.warn(
          `Threat detected and auto-responded: ${threat.attack_type} from ${threat.source_ip} ` +
          `(Risk: ${threat.risk_score.toFixed(1)}/100, Confidence: ${threat.confidence.toFixed(2)})`
        );
      } else {
        // Benign traffic - still broadcast for monitoring
        if (predictionEventHandler) {
          await predictionEventHandler.broadcastPrediction(org_id, threat);
        }
      }

      return threat;
    } catch (error) {
      this.errorCount++;
      logger.error(`Threat processing error: ${error}`);
      throw error;
    }
  }

  async processBatch(
    org_id: number,
    flows: NetworkFlow[],
    featuresList: number[][]
  ): Promise<ProcessedThreat[]> {
    const results: ProcessedThreat[] = [];

    for (let i = 0; i < flows.length; i++) {
      try {
        const threat = await this.processNetworkFlow(
          org_id,
          flows[i],
          featuresList[i]
        );

        if (threat) {
          results.push(threat);
        }
      } catch (error) {
        logger.warn(`Failed to process flow ${flows[i].flow_id}: ${error}`);
        this.errorCount++;
        // Continue processing remaining flows
      }
    }

    return results;
  }

  getStats(): {
    total_processed: number;
    total_threats: number;
    error_count: number;
    threat_rate: number;
    error_rate: number;
  } {
    return {
      total_processed: this.processedCount,
      total_threats: this.threatCount,
      error_count: this.errorCount,
      threat_rate: this.processedCount > 0 ? this.threatCount / this.processedCount : 0,
      error_rate: this.processedCount > 0 ? this.errorCount / this.processedCount : 0,
    };
  }

  reset(): void {
    this.processedCount = 0;
    this.threatCount = 0;
    this.errorCount = 0;
    logger.info('Threat processing stats reset');
  }

  async validateAIConnection(): Promise<boolean> {
    try {
      const isHealthy = await aiInferenceService.healthCheck();
      if (!isHealthy) {
        logger.warn('AI Inference service is not healthy');
      }
      return isHealthy;
    } catch (error) {
      logger.error(`Failed to validate AI connection: ${error}`);
      return false;
    }
  }
}

export const threatProcessingService = new ThreatProcessingService();

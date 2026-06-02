import axios, { AxiosInstance } from 'axios';
import { logger } from '../utils/logger';
import { AppError } from '../types';

interface NetworkFeature {
  features: number[];
  flow_id?: string;
  metadata?: Record<string, any>;
}

interface PredictionResult {
  attack_type: string;
  confidence: number;
  probability_distribution: Record<string, number>;
}

interface InferenceResponse {
  flow_id: string;
  lstm_prediction: PredictionResult;
  rf_prediction: PredictionResult;
  ensemble_prediction: PredictionResult;
  risk_score: number;
  risk_level: string;
  inference_time_ms: number;
  timestamp: string;
}

export class AIInferenceService {
  private client: AxiosInstance;
  private baseUrl: string;
  private timeout: number = 5000;

  constructor(aiServiceUrl?: string) {
    this.baseUrl = aiServiceUrl || process.env.AI_SERVICE_URL || 'http://localhost:5001';

    this.client = axios.create({
      baseURL: this.baseUrl,
      timeout: this.timeout,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.client.get('/health');
      logger.debug(`AI Service health: ${response.data.status}`);
      return response.data.status === 'healthy';
    } catch (error) {
      logger.warn(`AI Service health check failed: ${error}`);
      return false;
    }
  }

  async predict(
    features: number[],
    flowId?: string,
    metadata?: Record<string, any>
  ): Promise<InferenceResponse> {
    try {
      if (features.length !== 50) {
        throw new AppError(
          'INVALID_FEATURES',
          400,
          `Expected 50 features, got ${features.length}`
        );
      }

      const payload: NetworkFeature = {
        features,
        flow_id: flowId,
        metadata,
      };

      const response = await this.client.post<InferenceResponse>('/inference', payload);

      logger.debug(
        `Inference result: ${response.data.ensemble_prediction.attack_type} ` +
        `(conf: ${response.data.ensemble_prediction.confidence.toFixed(3)}, ` +
        `risk: ${response.data.risk_score.toFixed(1)})`
      );

      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        logger.error(`AI Service inference failed: ${error.message}`);
        throw new AppError(
          'AI_INFERENCE_ERROR',
          503,
          'Threat detection service unavailable'
        );
      }
      throw error;
    }
  }

  async predictBatch(
    featuresList: number[][],
    flowIds?: string[]
  ): Promise<InferenceResponse[]> {
    const results: InferenceResponse[] = [];

    for (let i = 0; i < featuresList.length; i++) {
      try {
        const result = await this.predict(
          featuresList[i],
          flowIds ? flowIds[i] : undefined
        );
        results.push(result);
      } catch (error) {
        logger.warn(`Batch inference failed for item ${i}: ${error}`);
        // Continue with next item instead of failing entire batch
      }
    }

    return results;
  }

  async getModels(): Promise<any> {
    try {
      const response = await this.client.get('/models');
      return response.data;
    } catch (error) {
      logger.error(`Failed to fetch model info: ${error}`);
      throw new AppError('AI_ERROR', 503, 'Could not fetch AI model information');
    }
  }

  async getStatus(): Promise<any> {
    try {
      const response = await this.client.get('/status');
      return response.data;
    } catch (error) {
      logger.error(`Failed to fetch AI status: ${error}`);
      throw new AppError('AI_ERROR', 503, 'Could not fetch AI service status');
    }
  }

  mapRiskLevelToSeverity(riskLevel: string): 'low' | 'medium' | 'high' | 'critical' {
    const mapping: Record<string, 'low' | 'medium' | 'high' | 'critical'> = {
      low: 'low',
      medium: 'medium',
      high: 'high',
      critical: 'critical',
    };
    return mapping[riskLevel] || 'medium';
  }

  mapAttackTypeToCategory(attackType: string): 'ddos' | 'sql_injection' | 'brute_force' | 'malware' | 'anomaly' {
    const mapping: Record<string, 'ddos' | 'sql_injection' | 'brute_force' | 'malware' | 'anomaly'> = {
      ddos: 'ddos',
      sql_injection: 'sql_injection',
      brute_force: 'brute_force',
      anomaly: 'anomaly',
      benign: 'anomaly', // Map benign to anomaly for consistency
    };
    return mapping[attackType] || 'anomaly';
  }

  calculateBlockDuration(riskScore: number, attackType: string): number {
    // Return block duration in minutes based on risk
    if (riskScore >= 80) return 720; // 12 hours
    if (riskScore >= 60) return 360; // 6 hours
    if (riskScore >= 40) return 60;  // 1 hour
    return 10; // 10 minutes
  }

  setServiceUrl(url: string): void {
    this.baseUrl = url;
    this.client.defaults.baseURL = url;
  }

  setTimeout(ms: number): void {
    this.timeout = ms;
    this.client.defaults.timeout = ms;
  }
}

export const aiInferenceService = new AIInferenceService();

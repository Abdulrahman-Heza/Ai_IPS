import { logger } from '../utils/logger';
import { redisClient } from '../database/redis';
import { AppError } from '../types';

interface DriftMetrics {
  timestamp: Date;
  total_predictions: number;
  benign_count: number;
  ddos_count: number;
  brute_force_count: number;
  sql_injection_count: number;
  anomaly_count: number;
  average_confidence: number;
  high_risk_percentage: number;
  model_version: string;
}

interface DriftAlert {
  timestamp: Date;
  metric_name: string;
  current_value: number;
  baseline_value: number;
  deviation: number;
  severity: 'low' | 'medium' | 'high';
  recommendation: string;
}

export class DriftDetectionService {
  private readonly METRICS_KEY = 'drift:metrics';
  private readonly ALERTS_KEY = 'drift:alerts';
  private readonly BASELINE_KEY = 'drift:baseline';
  private readonly RETENTION_DAYS = 30;

  // Baseline thresholds for drift detection
  private thresholds = {
    confidence_drop_threshold: 0.05,  // 5% drop in average confidence
    distribution_change: 0.10,        // 10% change in class distribution
    high_risk_increase: 0.15,         // 15% increase in high-risk predictions
  };

  async recordPrediction(
    prediction: {
      attack_type: string;
      confidence: number;
      risk_score: number;
      risk_level: string;
    },
    org_id: number
  ): Promise<void> {
    try {
      const metricsKey = `${this.METRICS_KEY}:${org_id}`;
      const now = new Date();
      const dateKey = now.toISOString().split('T')[0]; // YYYY-MM-DD

      // Increment counters
      const counterKey = `${metricsKey}:${dateKey}:counter`;
      await redisClient.incr(`${counterKey}:total`);

      if (prediction.attack_type === 'benign') {
        await redisClient.incr(`${counterKey}:benign`);
      } else if (prediction.attack_type === 'ddos') {
        await redisClient.incr(`${counterKey}:ddos`);
      } else if (prediction.attack_type === 'brute_force') {
        await redisClient.incr(`${counterKey}:brute_force`);
      } else if (prediction.attack_type === 'sql_injection') {
        await redisClient.incr(`${counterKey}:sql_injection`);
      } else if (prediction.attack_type === 'anomaly') {
        await redisClient.incr(`${counterKey}:anomaly`);
      }

      // Track confidence scores
      const confidenceKey = `${metricsKey}:${dateKey}:confidence`;
      await redisClient.lpush(confidenceKey, prediction.confidence.toString());
      await redisClient.expire(confidenceKey, 86400 * this.RETENTION_DAYS);

      // Track risk levels
      if (prediction.risk_score >= 60) {
        await redisClient.incr(`${counterKey}:high_risk`);
      }

      // Set expiry on counter key
      await redisClient.expire(counterKey, 86400 * this.RETENTION_DAYS);

      // Check for drift every 100 predictions
      const totalKey = `${counterKey}:total`;
      const total = await redisClient.get(totalKey);
      if (total && parseInt(total) % 100 === 0) {
        await this.checkForDrift(org_id);
      }
    } catch (error) {
      logger.warn(`Failed to record prediction for drift detection: ${error}`);
    }
  }

  async checkForDrift(org_id: number): Promise<DriftAlert[]> {
    try {
      const metrics = await this.getCurrentMetrics(org_id);
      const baseline = await this.getBaseline(org_id);

      if (!baseline) {
        // First time - set baseline
        await this.setBaseline(org_id, metrics);
        return [];
      }

      const alerts: DriftAlert[] = [];

      // Check 1: Confidence drop
      const confidenceDrop = baseline.average_confidence - metrics.average_confidence;
      if (confidenceDrop > this.thresholds.confidence_drop_threshold) {
        alerts.push({
          timestamp: new Date(),
          metric_name: 'average_confidence',
          current_value: metrics.average_confidence,
          baseline_value: baseline.average_confidence,
          deviation: confidenceDrop,
          severity: confidenceDrop > 0.10 ? 'high' : 'medium',
          recommendation: 'Model confidence is declining. Consider retraining with recent data.',
        });
      }

      // Check 2: Distribution shift (Benign ratio)
      const baselineBenignRatio = baseline.benign_count / baseline.total_predictions;
      const currentBenignRatio = metrics.benign_count / metrics.total_predictions;
      const benignShift = Math.abs(baselineBenignRatio - currentBenignRatio);

      if (benignShift > this.thresholds.distribution_change) {
        alerts.push({
          timestamp: new Date(),
          metric_name: 'benign_distribution',
          current_value: currentBenignRatio,
          baseline_value: baselineBenignRatio,
          deviation: benignShift,
          severity: benignShift > 0.15 ? 'high' : 'medium',
          recommendation: 'Traffic pattern has shifted. Network behavior may have changed.',
        });
      }

      // Check 3: High-risk prediction increase
      const baselineHighRiskPct = baseline.high_risk_percentage;
      const currentHighRiskPct = metrics.high_risk_percentage;
      const highRiskIncrease = currentHighRiskPct - baselineHighRiskPct;

      if (highRiskIncrease > this.thresholds.high_risk_increase) {
        alerts.push({
          timestamp: new Date(),
          metric_name: 'high_risk_percentage',
          current_value: currentHighRiskPct,
          baseline_value: baselineHighRiskPct,
          deviation: highRiskIncrease,
          severity: highRiskIncrease > 0.20 ? 'high' : 'medium',
          recommendation: 'Increase in threat detections. Verify model predictions with manual analysis.',
        });
      }

      // Store alerts if any detected
      if (alerts.length > 0) {
        await this.storeAlerts(org_id, alerts);
        alerts.forEach(alert => {
          logger.warn(`Drift detected for org ${org_id}: ${alert.metric_name}`);
        });
      }

      return alerts;
    } catch (error) {
      logger.error(`Drift detection failed: ${error}`);
      return [];
    }
  }

  private async getCurrentMetrics(org_id: number): Promise<DriftMetrics> {
    const now = new Date();
    const dateKey = now.toISOString().split('T')[0];
    const counterKey = `drift:metrics:${org_id}:${dateKey}:counter`;
    const confidenceKey = `drift:metrics:${org_id}:${dateKey}:confidence`;

    const total = parseInt(await redisClient.get(`${counterKey}:total`) || '0');
    const benign = parseInt(await redisClient.get(`${counterKey}:benign`) || '0');
    const ddos = parseInt(await redisClient.get(`${counterKey}:ddos`) || '0');
    const bruteForce = parseInt(await redisClient.get(`${counterKey}:brute_force`) || '0');
    const sqlInjection = parseInt(await redisClient.get(`${counterKey}:sql_injection`) || '0');
    const anomaly = parseInt(await redisClient.get(`${counterKey}:anomaly`) || '0');
    const highRisk = parseInt(await redisClient.get(`${counterKey}:high_risk`) || '0');

    // Get average confidence
    const confidenceScores = await redisClient.lrange(confidenceKey, 0, -1);
    const avgConfidence = confidenceScores.length > 0
      ? confidenceScores.reduce((sum, score) => sum + parseFloat(score), 0) / confidenceScores.length
      : 0.5;

    return {
      timestamp: now,
      total_predictions: total,
      benign_count: benign,
      ddos_count: ddos,
      brute_force_count: bruteForce,
      sql_injection_count: sqlInjection,
      anomaly_count: anomaly,
      average_confidence: avgConfidence,
      high_risk_percentage: total > 0 ? highRisk / total : 0,
      model_version: '2.0.0',
    };
  }

  private async getBaseline(org_id: number): Promise<DriftMetrics | null> {
    const baselineKey = `${this.BASELINE_KEY}:${org_id}`;
    const data = await redisClient.get(baselineKey);

    if (!data) {
      return null;
    }

    try {
      return JSON.parse(data);
    } catch {
      return null;
    }
  }

  private async setBaseline(org_id: number, metrics: DriftMetrics): Promise<void> {
    const baselineKey = `${this.BASELINE_KEY}:${org_id}`;
    await redisClient.set(baselineKey, JSON.stringify(metrics));
    logger.info(`Baseline set for org ${org_id}`);
  }

  private async storeAlerts(org_id: number, alerts: DriftAlert[]): Promise<void> {
    const alertsKey = `${this.ALERTS_KEY}:${org_id}`;

    for (const alert of alerts) {
      await redisClient.lpush(alertsKey, JSON.stringify(alert));
    }

    await redisClient.expire(alertsKey, 86400 * this.RETENTION_DAYS);
  }

  async getRecentAlerts(org_id: number, limit: number = 10): Promise<DriftAlert[]> {
    try {
      const alertsKey = `${this.ALERTS_KEY}:${org_id}`;
      const data = await redisClient.lrange(alertsKey, 0, limit - 1);

      return data.map(item => JSON.parse(item));
    } catch (error) {
      logger.error(`Failed to get drift alerts: ${error}`);
      return [];
    }
  }

  async resetBaseline(org_id: number): Promise<void> {
    const baselineKey = `${this.BASELINE_KEY}:${org_id}`;
    await redisClient.del(baselineKey);
    logger.info(`Baseline reset for org ${org_id}`);
  }

  setThreshold(metric: string, value: number): void {
    if (metric === 'confidence_drop') {
      this.thresholds.confidence_drop_threshold = value;
    } else if (metric === 'distribution_change') {
      this.thresholds.distribution_change = value;
    } else if (metric === 'high_risk_increase') {
      this.thresholds.high_risk_increase = value;
    }
  }
}

export const driftDetectionService = new DriftDetectionService();

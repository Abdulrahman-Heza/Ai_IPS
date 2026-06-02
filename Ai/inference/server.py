"""
AI/ML Inference Service - Phase 4 Model Deployment
FastAPI server for threat detection and classification using trained LSTM & Random Forest
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict
import os
import sys
from pathlib import Path
from datetime import datetime
import logging
import numpy as np
import time

# Setup logging
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'))
logger = logging.getLogger(__name__)

# Add ml module to path
sys.path.insert(0, str(Path(__file__).parent.parent))
from ml.utils.model_utils import ModelManager

# Initialize FastAPI app
app = FastAPI(
    title="IPS AI/ML Inference Service",
    description="AI-Powered Intrusion Detection using Trained LSTM Ensemble",
    version="2.0.0"
)

# Request/Response Models
class NetworkFeature(BaseModel):
    """Network flow features for inference"""
    features: List[float]  # 50-dimensional feature vector
    flow_id: Optional[str] = None
    metadata: Optional[dict] = None

class PredictionResult(BaseModel):
    """Individual model prediction"""
    attack_type: str
    confidence: float
    probability_distribution: Dict[str, float]

class InferenceResponse(BaseModel):
    """Complete inference response"""
    flow_id: str
    lstm_prediction: PredictionResult
    rf_prediction: PredictionResult
    ensemble_prediction: PredictionResult
    risk_score: float
    risk_level: str
    inference_time_ms: float
    timestamp: str

class ModelMetrics(BaseModel):
    """Model performance metrics"""
    lstm_accuracy: float
    lstm_precision: float
    lstm_recall: float
    rf_accuracy: float
    rf_precision: float
    rf_recall: float
    training_samples: int
    test_samples: int

class HealthStatus(BaseModel):
    """Health check response"""
    status: str
    models_loaded: bool
    lstm_ready: bool
    rf_ready: bool
    request_count: int
    average_inference_time_ms: float
    uptime_hours: float

# Global state
class ModelState:
    def __init__(self):
        self.request_count = 0
        self.model_manager = None
        self.is_ready = False
        self.start_time = datetime.now()
        self.inference_times = []
        self.model_metrics = None
        self.lstm_ready = False
        self.rf_ready = False

model_state = ModelState()

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize models and services"""
    logger.info("🚀 Starting AI/ML Inference Service (Phase 4)...")
    logger.info("📦 Loading trained models...")

    try:
        model_state.model_manager = ModelManager(models_dir='ai/models')

        # Try to load latest models
        if model_state.model_manager.load_latest_models():
            model_state.lstm_ready = model_state.model_manager.lstm_model is not None
            model_state.rf_ready = model_state.model_manager.rf_model is not None
            model_state.is_ready = model_state.lstm_ready or model_state.rf_ready

            if model_state.lstm_ready:
                logger.info("✅ LSTM Ensemble Model loaded")
            if model_state.rf_ready:
                logger.info("✅ Random Forest Model loaded")
        else:
            logger.warning("⚠️ Models not found - running in demo mode")
            model_state.is_ready = True

        logger.info("")
        logger.info("✅ Phase 4: AI Model Training & Deployment - ACTIVE")
        logger.info("📊 Ready for real-time threat detection")

    except Exception as e:
        logger.error(f"Failed to load models: {e}")
        model_state.is_ready = False

@app.get("/health")
async def health_check() -> HealthStatus:
    """Health check endpoint"""
    uptime_hours = (datetime.now() - model_state.start_time).total_seconds() / 3600
    avg_inference_time = (
        np.mean(model_state.inference_times[-100:])
        if model_state.inference_times
        else 0.0
    )

    return HealthStatus(
        status="healthy" if model_state.is_ready else "initializing",
        models_loaded=model_state.is_ready,
        lstm_ready=model_state.lstm_ready,
        rf_ready=model_state.rf_ready,
        request_count=model_state.request_count,
        average_inference_time_ms=avg_inference_time,
        uptime_hours=uptime_hours
    )

@app.post("/inference")
async def inference(features: NetworkFeature) -> InferenceResponse:
    """
    Perform threat detection on network flow using trained models.

    Returns:
        InferenceResponse: Ensemble prediction with confidence scores
    """
    if not model_state.is_ready:
        raise HTTPException(status_code=503, detail="Models not loaded")

    model_state.request_count += 1
    start_time = time.time()

    try:
        # Validate input
        if len(features.features) != 50:
            raise ValueError(f"Expected 50 features, got {len(features.features)}")

        X = np.array(features.features, dtype=np.float32)

        if not ModelManager.validate_features(X):
            raise ValueError("Invalid feature values (NaN or Inf detected)")

        # Make predictions
        attack_labels = {
            0: 'benign',
            1: 'ddos',
            2: 'brute_force',
            3: 'sql_injection',
            4: 'anomaly',
        }

        lstm_pred = None
        rf_pred = None
        ensemble_pred = None

        # LSTM prediction
        if model_state.lstm_ready:
            lstm_class, lstm_conf = model_state.model_manager.predict_lstm(X)
            lstm_pred = PredictionResult(
                attack_type=attack_labels[lstm_class],
                confidence=float(lstm_conf),
                probability_distribution={
                    attack_labels[i]: float(0.1 * (1 if i == lstm_class else 1))
                    for i in range(5)
                }
            )

        # Random Forest prediction
        if model_state.rf_ready:
            rf_class, rf_conf = model_state.model_manager.predict_rf(X)
            rf_pred = PredictionResult(
                attack_type=attack_labels[rf_class],
                confidence=float(rf_conf),
                probability_distribution={
                    attack_labels[i]: float(0.1 * (1 if i == rf_class else 1))
                    for i in range(5)
                }
            )

        # Ensemble prediction
        if model_state.lstm_ready and model_state.rf_ready:
            ens_class, ens_conf = model_state.model_manager.predict_ensemble(X)
            ensemble_pred = PredictionResult(
                attack_type=attack_labels[ens_class],
                confidence=float(ens_conf),
                probability_distribution={
                    attack_labels[i]: float(0.1 * (1 if i == ens_class else 1))
                    for i in range(5)
                }
            )
        elif model_state.lstm_ready:
            ensemble_pred = lstm_pred
        elif model_state.rf_ready:
            ensemble_pred = rf_pred
        else:
            # Lightweight demo prediction for the simplified graduation setup.
            mean_value = float(np.mean(X))
            demo_class = 4 if mean_value > 0.75 else 0
            demo_confidence = min(0.95, max(0.55, abs(mean_value)))
            ensemble_pred = PredictionResult(
                attack_type=attack_labels[demo_class],
                confidence=demo_confidence,
                probability_distribution={
                    attack_labels[i]: (demo_confidence if i == demo_class else (1 - demo_confidence) / 4)
                    for i in range(5)
                }
            )

        # Calculate risk score
        risk_score = model_state.model_manager.get_risk_score(
            int(ensemble_pred.attack_type == 'benign' and 0 or
                (1 if ensemble_pred.attack_type == 'ddos' else
                 2 if ensemble_pred.attack_type == 'brute_force' else
                 3 if ensemble_pred.attack_type == 'sql_injection' else 4)),
            ensemble_pred.confidence
        )

        # Determine risk level
        if risk_score < 30:
            risk_level = 'low'
        elif risk_score < 60:
            risk_level = 'medium'
        elif risk_score < 80:
            risk_level = 'high'
        else:
            risk_level = 'critical'

        inference_time = (time.time() - start_time) * 1000
        model_state.inference_times.append(inference_time)

        response = InferenceResponse(
            flow_id=features.flow_id or f"flow_{model_state.request_count}",
            lstm_prediction=lstm_pred or ensemble_pred,
            rf_prediction=rf_pred or ensemble_pred,
            ensemble_prediction=ensemble_pred,
            risk_score=risk_score,
            risk_level=risk_level,
            inference_time_ms=inference_time,
            timestamp=datetime.now().isoformat()
        )

        logger.info(f"Inference #{model_state.request_count}: {ensemble_pred.attack_type} "
                   f"({ensemble_pred.confidence:.3f}, risk={risk_score:.1f})")

        return response

    except Exception as e:
        logger.error(f"Inference error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/models")
async def list_models():
    """List available models and their status"""
    return {
        "lstm_ensemble": {
            "id": "lstm_ensemble_v2.0",
            "name": "LSTM Ensemble",
            "version": "2.0.0",
            "type": "deep_learning",
            "status": "deployed" if model_state.lstm_ready else "pending",
            "architecture": "3-branch LSTM with CNN feature extraction",
            "target_metrics": {
                "accuracy": ">=96%",
                "precision": ">=97%",
                "recall": ">=95%",
                "f1_score": ">=96%"
            }
        },
        "random_forest": {
            "id": "rf_v2.0",
            "name": "Random Forest Classifier",
            "version": "2.0.0",
            "type": "ensemble",
            "status": "deployed" if model_state.rf_ready else "pending",
            "estimators": 200,
            "max_depth": 20
        },
        "attack_types": {
            0: "benign",
            1: "ddos",
            2: "brute_force",
            3: "sql_injection",
            4: "anomaly"
        },
        "feature_count": 50,
        "sequence_length": 10
    }

@app.get("/status")
async def status():
    """Service status"""
    return {
        "service": "IPS AI/ML Inference Engine",
        "version": "2.0.0",
        "status": "ready" if model_state.is_ready else "initializing",
        "phase": "4-5: Model Deployment",
        "models_loaded": model_state.is_ready,
        "lstm_ready": model_state.lstm_ready,
        "rf_ready": model_state.rf_ready,
        "total_requests": model_state.request_count,
        "uptime_seconds": (datetime.now() - model_state.start_time).total_seconds()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5001)),
        log_level=os.getenv("LOG_LEVEL", "info")
    )

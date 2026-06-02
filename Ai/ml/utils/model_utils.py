import numpy as np
import json
import logging
from pathlib import Path
from typing import Optional, Tuple, Dict

logger = logging.getLogger(__name__)


class ModelManager:
    """Manages model loading, inference, and versioning."""

    def __init__(self, models_dir: str = 'ai/models'):
        self.models_dir = Path(models_dir)
        self.lstm_model = None
        self.rf_model = None
        self.normalization = None
        self.feature_names = None

    def load_models(self, lstm_path: str = None, rf_path: str = None,
                   norm_path: str = None) -> bool:
        """Load all models and normalization parameters."""
        try:
            if lstm_path:
                import tensorflow as tf
                self.lstm_model = tf.keras.models.load_model(lstm_path)
                logger.info(f"Loaded LSTM model: {lstm_path}")

            if rf_path:
                import joblib
                self.rf_model = joblib.load(rf_path)
                logger.info(f"Loaded Random Forest: {rf_path}")

            if norm_path:
                with open(norm_path, 'r') as f:
                    norm_data = json.load(f)
                    self.normalization = {
                        'mean': np.array(norm_data['mean'], dtype=np.float32),
                        'std': np.array(norm_data['std'], dtype=np.float32),
                    }
                logger.info(f"Loaded normalization: {norm_path}")

            return True

        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            return False

    def load_latest_models(self) -> bool:
        """Auto-load the most recent models."""
        try:
            # Find latest model files
            lstm_files = list(self.models_dir.glob('lstm_ensemble_*.h5'))
            rf_files = list(self.models_dir.glob('random_forest_*.joblib'))
            norm_files = list(self.models_dir.glob('normalization_*.json'))

            lstm_path = max(lstm_files) if lstm_files else None
            rf_path = max(rf_files) if rf_files else None
            norm_path = max(norm_files) if norm_files else None

            return self.load_models(str(lstm_path), str(rf_path), str(norm_path))

        except Exception as e:
            logger.error(f"Failed to load latest models: {e}")
            return False

    def normalize_features(self, X: np.ndarray) -> np.ndarray:
        """Apply stored normalization to features."""
        if self.normalization is None:
            logger.warning("No normalization parameters loaded")
            return X

        mean = self.normalization['mean']
        std = self.normalization['std']

        X_norm = (X - mean) / std
        return np.nan_to_num(X_norm, nan=0.0, posinf=0.0, neginf=0.0)

    def create_sequence(self, X: np.ndarray, seq_length: int = 10) -> np.ndarray:
        """Convert feature vector to sequence for LSTM."""
        if len(X.shape) == 1:
            # Single sample
            X = np.expand_dims(X, axis=0)

        # Pad if necessary
        if X.shape[0] < seq_length:
            padding = np.zeros((seq_length - X.shape[0], X.shape[1]))
            X = np.vstack([X, padding])

        # Take last seq_length samples
        return np.expand_dims(X[-seq_length:], axis=0).astype(np.float32)

    def predict_lstm(self, X: np.ndarray, seq_length: int = 10) -> Tuple[int, float]:
        """
        Make LSTM prediction.
        Args:
            X: (50,) feature vector or (n_samples, 50) batch
            seq_length: Sequence length for LSTM

        Returns:
            (predicted_class, confidence_score)
        """
        if self.lstm_model is None:
            raise ValueError("LSTM model not loaded")

        # Normalize
        X = self.normalize_features(X)

        # Create sequence
        X_seq = self.create_sequence(X, seq_length)

        # Predict
        probs = self.lstm_model.predict(X_seq, verbose=0)
        prediction = np.argmax(probs[0])
        confidence = float(np.max(probs[0]))

        return int(prediction), confidence

    def predict_rf(self, X: np.ndarray) -> Tuple[int, float]:
        """
        Make Random Forest prediction.
        Args:
            X: (50,) feature vector or (n_samples, 50) batch

        Returns:
            (predicted_class, confidence_score)
        """
        if self.rf_model is None:
            raise ValueError("Random Forest model not loaded")

        # Normalize
        X = self.normalize_features(X)

        # Flatten for Random Forest
        if len(X.shape) == 1:
            X = X.reshape(1, -1)

        # Predict
        probs = self.rf_model.predict_proba(X)
        prediction = self.rf_model.predict(X)[0]
        confidence = float(np.max(probs[0]))

        return int(prediction), confidence

    def predict_ensemble(self, X: np.ndarray, lstm_weight: float = 0.7) -> Tuple[int, float]:
        """
        Ensemble prediction from LSTM and Random Forest.
        Args:
            X: (50,) feature vector
            lstm_weight: Weight for LSTM prediction (0-1)

        Returns:
            (predicted_class, confidence_score)
        """
        lstm_pred, lstm_conf = self.predict_lstm(X)
        rf_pred, rf_conf = self.predict_rf(X)

        # Weighted ensemble
        if lstm_pred == rf_pred:
            # Models agree
            final_pred = lstm_pred
            final_conf = (lstm_conf * lstm_weight + rf_conf * (1 - lstm_weight))
        else:
            # Models disagree - use higher confidence
            if lstm_conf >= rf_conf:
                final_pred = lstm_pred
                final_conf = lstm_conf * lstm_weight
            else:
                final_pred = rf_pred
                final_conf = rf_conf * (1 - lstm_weight)

        return final_pred, final_conf

    def get_risk_score(self, prediction: int, confidence: float) -> float:
        """
        Convert prediction to risk score (0-100).
        Benign: 0-20
        SQL Injection: 80-100
        DDoS: 70-100
        Brute Force: 70-100
        Anomaly: 60-100
        """
        attack_type_scores = {
            0: (0, 20),      # benign
            1: (70, 100),    # ddos
            2: (70, 100),    # brute_force
            3: (80, 100),    # sql_injection
            4: (60, 100),    # anomaly
        }

        min_score, max_score = attack_type_scores.get(prediction, (0, 100))
        risk_score = min_score + (max_score - min_score) * confidence

        return float(risk_score)

    def get_attack_label(self, prediction: int) -> str:
        """Get human-readable attack type label."""
        labels = {
            0: 'benign',
            1: 'ddos',
            2: 'brute_force',
            3: 'sql_injection',
            4: 'anomaly',
        }
        return labels.get(prediction, 'unknown')

    @staticmethod
    def validate_features(X: np.ndarray) -> bool:
        """Validate feature vector shape and values."""
        if X.shape[-1] != 50:
            return False
        if np.any(np.isnan(X)) or np.any(np.isinf(X)):
            return False
        return True

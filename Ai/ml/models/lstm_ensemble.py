import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, models
import numpy as np
from typing import Tuple
import logging

logger = logging.getLogger(__name__)


class LSTMEnsemble:
    """
    LSTM Ensemble model for intrusion detection.
    Combines multiple LSTM stacks with 1D-CNN layers.
    Target metrics: 96% accuracy, 97% precision, 95% recall, 96% F1-score.
    """

    def __init__(self, input_shape: Tuple[int, int] = (10, 50),
                 num_classes: int = 5,
                 lstm_units: int = 128,
                 dropout_rate: float = 0.3):
        """
        Args:
            input_shape: (sequence_length, num_features)
            num_classes: 5 (benign, ddos, brute_force, sql_injection, anomaly)
            lstm_units: Units per LSTM layer
            dropout_rate: Dropout rate for regularization
        """
        self.input_shape = input_shape
        self.num_classes = num_classes
        self.lstm_units = lstm_units
        self.dropout_rate = dropout_rate
        self.model = None

    def build_model(self) -> models.Model:
        """
        Build LSTM Ensemble architecture:
        - Input: (batch, seq_len, 50)
        - 2 parallel LSTM branches with different configurations
        - 1D-CNN feature extraction
        - Dense layers with attention
        - Output: (batch, 5) class probabilities
        """
        inputs = layers.Input(shape=self.input_shape, name='flow_input')

        # Branch 1: Deep LSTM stack
        lstm1 = layers.LSTM(self.lstm_units, return_sequences=True,
                           activation='relu', name='lstm1_1')(inputs)
        dropout1 = layers.Dropout(self.dropout_rate)(lstm1)
        lstm2 = layers.LSTM(self.lstm_units // 2, return_sequences=True,
                           activation='relu', name='lstm1_2')(dropout1)
        dropout2 = layers.Dropout(self.dropout_rate)(lstm2)
        lstm3 = layers.LSTM(self.lstm_units // 4, activation='relu',
                           name='lstm1_3')(dropout2)

        # Branch 2: CNN-based temporal feature extraction
        conv1 = layers.Conv1D(64, kernel_size=3, activation='relu',
                             padding='same', name='conv1d_1')(inputs)
        conv2 = layers.Conv1D(32, kernel_size=3, activation='relu',
                             padding='same', name='conv1d_2')(conv1)
        pool = layers.MaxPooling1D(pool_size=2, padding='same')(conv2)
        flat = layers.Flatten()(pool)

        # Branch 3: Alternative LSTM configuration
        lstm4 = layers.LSTM(self.lstm_units // 2, return_sequences=True,
                           activation='tanh', name='lstm2_1')(inputs)
        dropout3 = layers.Dropout(self.dropout_rate)(lstm4)
        lstm5 = layers.LSTM(self.lstm_units // 4, activation='tanh',
                           name='lstm2_2')(dropout3)

        # Merge branches
        merged = layers.Concatenate(name='merge')([lstm3, flat, lstm5])

        # Dense layers with regularization
        dense1 = layers.Dense(256, activation='relu', name='dense1')(merged)
        dropout4 = layers.Dropout(self.dropout_rate)(dense1)

        dense2 = layers.Dense(128, activation='relu', name='dense2')(dropout4)
        dropout5 = layers.Dropout(self.dropout_rate)(dense2)

        dense3 = layers.Dense(64, activation='relu', name='dense3')(dropout5)

        # Output layer with softmax
        outputs = layers.Dense(self.num_classes, activation='softmax',
                              name='classification')(dense3)

        model = models.Model(inputs=inputs, outputs=outputs, name='lstm_ensemble')

        return model

    def compile_model(self, learning_rate: float = 0.001) -> None:
        """Compile model with optimized hyperparameters."""
        if self.model is None:
            self.model = self.build_model()

        optimizer = keras.optimizers.Adam(learning_rate=learning_rate)

        # Only 'accuracy' here — Precision/Recall/AUC with multi-class sparse
        # labels crash in Keras 3 due to confusion-matrix shape mismatch.
        # They are computed properly via sklearn in evaluate().
        self.model.compile(
            optimizer=optimizer,
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy'],
        )

    def train(self, X_train: np.ndarray, y_train: np.ndarray,
             X_val: np.ndarray, y_val: np.ndarray,
             epochs: int = 50, batch_size: int = 32) -> dict:
        """
        Train the LSTM ensemble model.

        Args:
            X_train: (n_train, seq_len, 50)
            y_train: (n_train,)
            X_val: (n_val, seq_len, 50)
            y_val: (n_val,)
            epochs: Training epochs
            batch_size: Batch size

        Returns:
            Training history dictionary
        """
        if self.model is None:
            self.compile_model()

        # Early stopping
        early_stop = keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=10,
            restore_best_weights=True
        )

        # Reduce learning rate on plateau
        reduce_lr = keras.callbacks.ReduceLROnPlateau(
            monitor='val_loss',
            factor=0.5,
            patience=5,
            min_lr=1e-7,
            verbose=1
        )

        # Class weight balancing (capped at 10x to avoid over-penalizing majority class)
        unique, counts = np.unique(y_train, return_counts=True)
        raw_weights = {
            int(label): len(y_train) / (len(unique) * count)
            for label, count in zip(unique, counts)
        }
        max_weight = max(raw_weights.values())
        class_weight = {
            lbl: min(w, 10.0) if max_weight > 10.0 else w
            for lbl, w in raw_weights.items()
        }

        logger.info(f"Class weights (raw): {raw_weights}")
        logger.info(f"Class weights (capped): {class_weight}")

        history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            class_weight=class_weight,
            callbacks=[early_stop, reduce_lr],
            verbose=1
        )

        return history.history

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> dict:
        """
        Evaluate model on test set.

        Returns:
            Dictionary with metrics: accuracy, precision, recall, f1, auc
        """
        if self.model is None:
            raise ValueError("Model not built or trained")

        from sklearn.metrics import (
            precision_score, recall_score, f1_score, roc_auc_score,
        )

        # Loss + accuracy from Keras
        results = self.model.evaluate(X_test, y_test, verbose=0)

        # Predictions for sklearn metrics
        probs = self.model.predict(X_test, verbose=0)          # (n, 5)
        y_pred = np.argmax(probs, axis=1)

        precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        recall    = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1        = f1_score(y_test, y_pred, average='weighted', zero_division=0)

        # Macro-average OvR AUC (needs probability scores)
        try:
            auc = roc_auc_score(y_test, probs, multi_class='ovr', average='weighted')
        except Exception:
            auc = 0.0

        metrics = {
            'loss':      float(results[0]),
            'accuracy':  float(results[1]),
            'precision': float(precision),
            'recall':    float(recall),
            'f1':        float(f1),
            'auc':       float(auc),
        }

        logger.info("Test Results:")
        logger.info(f"  Accuracy:  {metrics['accuracy']:.4f}")
        logger.info(f"  Precision: {metrics['precision']:.4f}")
        logger.info(f"  Recall:    {metrics['recall']:.4f}")
        logger.info(f"  F1-Score:  {metrics['f1']:.4f}")
        logger.info(f"  AUC:       {metrics['auc']:.4f}")

        return metrics

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Make predictions on new data.

        Args:
            X: (n_samples, seq_len, 50)

        Returns:
            (predictions, confidence_scores)
            predictions: (n_samples,) class labels
            confidence_scores: (n_samples,) confidence 0-1
        """
        if self.model is None:
            raise ValueError("Model not built or trained")

        probs = self.model.predict(X)
        predictions = np.argmax(probs, axis=1)
        confidence = np.max(probs, axis=1)

        return predictions, confidence

    def save_model(self, path: str) -> None:
        """Save model to disk."""
        if self.model is None:
            raise ValueError("No model to save")

        self.model.save(path)
        logger.info(f"Model saved to {path}")

    def load_model(self, path: str) -> None:
        """Load model from disk."""
        self.model = keras.models.load_model(path)
        logger.info(f"Model loaded from {path}")

    def summary(self) -> None:
        """Print model architecture."""
        if self.model is None:
            self.build_model()

        self.model.summary()

    def get_model(self) -> models.Model:
        """Return Keras model object."""
        if self.model is None:
            self.compile_model()
        return self.model


class RandomForestModel:
    """
    Random Forest classifier as fallback/ensemble model.
    Used for validation and as secondary detector.
    """

    def __init__(self, n_estimators: int = 200, max_depth: int = 20):
        from sklearn.ensemble import RandomForestClassifier
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=42,
            n_jobs=-1,
            verbose=1
        )

    def train(self, X_train: np.ndarray, y_train: np.ndarray) -> None:
        """Train Random Forest on flattened features."""
        X_flat = X_train.reshape(X_train.shape[0], -1)
        self.model.fit(X_flat, y_train)
        logger.info("Random Forest trained")

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict and return probabilities."""
        X_flat = X.reshape(X.shape[0], -1)
        probs = self.model.predict_proba(X_flat)
        predictions = self.model.predict(X_flat)
        confidence = np.max(probs, axis=1)
        return predictions, confidence

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> dict:
        """Evaluate on test set."""
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

        X_flat = X_test.reshape(X_test.shape[0], -1)
        pred = self.model.predict(X_flat)

        return {
            'accuracy': float(accuracy_score(y_test, pred)),
            'precision': float(precision_score(y_test, pred, average='weighted')),
            'recall': float(recall_score(y_test, pred, average='weighted')),
            'f1': float(f1_score(y_test, pred, average='weighted')),
        }

    def save_model(self, path: str) -> None:
        """Save model using joblib."""
        import joblib
        joblib.dump(self.model, path)
        logger.info(f"Random Forest saved to {path}")

    def load_model(self, path: str) -> None:
        """Load model from joblib."""
        import joblib
        self.model = joblib.load(path)
        logger.info(f"Random Forest loaded from {path}")

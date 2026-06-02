import numpy as np
import pandas as pd
from typing import Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)


class FeatureEngineer:
    """
    Extracts 50-dimensional feature vectors from network flow data.
    Implements protocol-level, traffic-level, and temporal features.
    """

    FLOW_FEATURES = [
        # Protocol Features (5)
        'protocol_type',  # 0=TCP, 1=UDP, 2=ICMP
        'service_code',   # Port-based service classification
        'flag_count',     # TCP flags present

        # Basic Flow Statistics (8)
        'duration',
        'src_bytes',
        'dst_bytes',
        'total_bytes',
        'bytes_ratio',    # dst_bytes / src_bytes
        'packet_count',
        'src_packets',
        'dst_packets',

        # Rate & Pattern Features (8)
        'packets_per_sec',
        'bytes_per_packet_src',
        'bytes_per_packet_dst',
        'avg_packet_size',
        'packet_size_variance',
        'inter_arrival_time',
        'urgent_count',
        'ack_count',

        # TCP Flag Features (6)
        'syn_count',
        'fin_count',
        'rst_count',
        'psh_count',
        'urg_count',
        'ece_count',

        # Window & Payload Features (5)
        'src_window_size',
        'dst_window_size',
        'payload_bytes',
        'payload_ratio',  # payload / total_bytes
        'zero_window_count',

        # Entropy & Distribution (4)
        'src_port_entropy',
        'dst_port_entropy',
        'payload_entropy',
        'packet_length_entropy',

        # State & Error Features (4)
        'invalid_checksum',
        'connection_state',  # 0=normal, 1=established, 2=reset, 3=closed
        'retransmission_count',
        'out_of_order_packets',
    ]

    NUM_FEATURES = len(FLOW_FEATURES)

    @staticmethod
    def extract_protocol_features(row: Dict) -> Dict[str, float]:
        """Extract protocol-level features."""
        features = {}

        # Protocol type encoding
        protocol = str(row.get('Protocol', 'TCP')).upper()
        features['protocol_type'] = {'TCP': 0, 'UDP': 1, 'ICMP': 2}.get(protocol, 0)

        # Service classification based on destination port
        dst_port = int(row.get('Dst Port', 80))
        service_map = {
            22: 1, 25: 2, 53: 3, 80: 4, 110: 5,
            143: 6, 443: 7, 445: 8, 465: 9, 587: 10
        }
        features['service_code'] = service_map.get(dst_port, 0)

        # TCP flags
        flags = str(row.get('Flags', 'F')).upper()
        features['flag_count'] = len(set(flags))

        return features

    @staticmethod
    def extract_flow_statistics(row: Dict) -> Dict[str, float]:
        """Extract basic flow statistics."""
        features = {}

        duration = max(float(row.get('Fwd Flow Duration', 0)) / 1_000_000, 0.001)
        src_bytes = max(float(row.get('Fwd Packet Length Mean', 0)), 0)
        dst_bytes = max(float(row.get('Bwd Packet Length Mean', 0)), 0)

        features['duration'] = duration
        features['src_bytes'] = src_bytes
        features['dst_bytes'] = dst_bytes
        features['total_bytes'] = src_bytes + dst_bytes
        features['bytes_ratio'] = (dst_bytes / src_bytes) if src_bytes > 0 else 0

        src_packets = max(float(row.get('Fwd Header Length', 0)), 1)
        dst_packets = max(float(row.get('Bwd Header Length', 0)), 1)

        features['packet_count'] = src_packets + dst_packets
        features['src_packets'] = src_packets
        features['dst_packets'] = dst_packets

        return features

    @staticmethod
    def extract_rate_features(row: Dict) -> Dict[str, float]:
        """Extract rate and pattern features."""
        features = {}

        duration = max(float(row.get('Fwd Flow Duration', 0)) / 1_000_000, 0.001)
        packet_count = max(float(row.get('Total Fwd Packets', 1)), 1)
        total_bytes = float(row.get('Total Length of Fwd Packets', 0)) + \
                     float(row.get('Total Length of Bwd Packets', 0))

        features['packets_per_sec'] = packet_count / duration
        features['bytes_per_packet_src'] = float(row.get('Fwd Packet Length Mean', 0))
        features['bytes_per_packet_dst'] = float(row.get('Bwd Packet Length Mean', 0))
        features['avg_packet_size'] = (total_bytes / packet_count) if packet_count > 0 else 0

        src_std = float(row.get('Fwd Packet Length Std', 0))
        dst_std = float(row.get('Bwd Packet Length Std', 0))
        features['packet_size_variance'] = (src_std ** 2 + dst_std ** 2) / 2

        features['inter_arrival_time'] = duration / max(packet_count - 1, 1)
        features['urgent_count'] = float(row.get('Fwd PSH Flags', 0)) + \
                                  float(row.get('Bwd PSH Flags', 0))
        features['ack_count'] = float(row.get('Fwd ACK Flags', 0)) + \
                               float(row.get('Bwd ACK Flags', 0))

        return features

    @staticmethod
    def extract_tcp_flags(row: Dict) -> Dict[str, float]:
        """Extract TCP flag features."""
        features = {}
        features['syn_count'] = float(row.get('Fwd SYN Flags', 0))
        features['fin_count'] = float(row.get('Fwd FIN Flags', 0))
        features['rst_count'] = float(row.get('Fwd RST Flags', 0))
        features['psh_count'] = float(row.get('Fwd PSH Flags', 0))
        features['urg_count'] = float(row.get('Fwd URG Flags', 0))
        features['ece_count'] = float(row.get('Fwd CWE Flag Count', 0))
        return features

    @staticmethod
    def extract_window_features(row: Dict) -> Dict[str, float]:
        """Extract window and payload features."""
        features = {}
        features['src_window_size'] = float(row.get('Fwd Init Win Bytes', 0))
        features['dst_window_size'] = float(row.get('Bwd Init Win Bytes', 0))

        total_bytes = float(row.get('Total Length of Fwd Packets', 0)) + \
                     float(row.get('Total Length of Bwd Packets', 0))
        features['payload_bytes'] = max(total_bytes - 40, 0)  # Subtract headers
        features['payload_ratio'] = (features['payload_bytes'] / total_bytes) if total_bytes > 0 else 0
        features['zero_window_count'] = float(row.get('Init Win Bytes Forward', 0))

        return features

    @staticmethod
    def extract_entropy_features(row: Dict) -> Dict[str, float]:
        """Extract entropy and distribution features."""
        features = {}

        # Simplified entropy calculations
        features['src_port_entropy'] = float(row.get('Src Port', 1)) % 256 / 256.0
        features['dst_port_entropy'] = float(row.get('Dst Port', 80)) % 256 / 256.0

        avg_pkt = float(row.get('Fwd Packet Length Mean', 0))
        features['payload_entropy'] = (avg_pkt % 256 / 256.0) if avg_pkt > 0 else 0

        std_pkt = float(row.get('Fwd Packet Length Std', 0))
        features['packet_length_entropy'] = min(std_pkt / 256.0, 1.0)

        return features

    @staticmethod
    def extract_state_features(row: Dict) -> Dict[str, float]:
        """Extract state and error features."""
        features = {}
        features['invalid_checksum'] = float(row.get('Inbound', 0))

        # Connection state based on flags and flow
        flags = str(row.get('Flags', '')).upper()
        if 'R' in flags:
            features['connection_state'] = 2  # Reset
        elif 'F' in flags:
            features['connection_state'] = 3  # Closed
        elif 'A' in flags:
            features['connection_state'] = 1  # Established
        else:
            features['connection_state'] = 0  # Normal

        features['retransmission_count'] = float(row.get('Fwd Header Length', 0))
        features['out_of_order_packets'] = float(row.get('Bwd Header Length', 0))

        return features

    @classmethod
    def extract_features(cls, row: Dict) -> np.ndarray:
        """
        Extract all 50 features from a network flow row.
        Returns normalized feature vector.
        """
        try:
            feature_dict = {}

            # Extract feature groups
            feature_dict.update(cls.extract_protocol_features(row))
            feature_dict.update(cls.extract_flow_statistics(row))
            feature_dict.update(cls.extract_rate_features(row))
            feature_dict.update(cls.extract_tcp_flags(row))
            feature_dict.update(cls.extract_window_features(row))
            feature_dict.update(cls.extract_entropy_features(row))
            feature_dict.update(cls.extract_state_features(row))

            # Build feature vector in correct order
            feature_vector = np.array([
                feature_dict.get(feat, 0.0) for feat in cls.FLOW_FEATURES
            ], dtype=np.float32)

            # Handle NaN and Inf
            feature_vector = np.nan_to_num(feature_vector, nan=0.0, posinf=0.0, neginf=0.0)

            return feature_vector

        except Exception as e:
            logger.warning(f"Feature extraction error: {e}, returning zero vector")
            return np.zeros(cls.NUM_FEATURES, dtype=np.float32)

    @classmethod
    def extract_batch(cls, df: pd.DataFrame) -> np.ndarray:
        """
        Extract features from DataFrame batch.
        Returns (batch_size, 50) array.
        """
        features = []
        for _, row in df.iterrows():
            features.append(cls.extract_features(row.to_dict()))

        return np.array(features, dtype=np.float32)

    @staticmethod
    def normalize_features(X: np.ndarray, mean: np.ndarray = None,
                          std: np.ndarray = None) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Z-score normalization of features.
        Returns normalized array and normalization parameters.
        """
        if mean is None:
            mean = np.mean(X, axis=0)
        if std is None:
            std = np.std(X, axis=0)

        # Avoid division by zero
        std = np.where(std == 0, 1.0, std)

        X_normalized = (X - mean) / std
        return X_normalized, mean, std

    @staticmethod
    def create_sequences(X: np.ndarray, y: np.ndarray = None,
                        seq_length: int = 10) -> Tuple[np.ndarray, np.ndarray]:
        """
        Create sequences for LSTM input.
        Shapes: X (n_samples - seq_length, seq_length, 50), y (n_samples - seq_length,)
        """
        X_seq = []
        y_seq = []

        for i in range(len(X) - seq_length):
            X_seq.append(X[i:i + seq_length])
            if y is not None:
                y_seq.append(y[i + seq_length])

        X_seq = np.array(X_seq, dtype=np.float32)
        y_seq = np.array(y_seq, dtype=np.float32) if y is not None else None

        return X_seq, y_seq

    @staticmethod
    def get_feature_names() -> List[str]:
        """Return list of feature names."""
        return FeatureEngineer.FLOW_FEATURES

    @staticmethod
    def get_feature_importance_baseline() -> Dict[str, float]:
        """Return baseline feature importance weights."""
        return {
            'src_bytes': 0.08,
            'dst_bytes': 0.08,
            'packets_per_sec': 0.07,
            'bytes_ratio': 0.07,
            'syn_count': 0.06,
            'fin_count': 0.05,
            'rst_count': 0.05,
            'packet_count': 0.05,
            'avg_packet_size': 0.05,
            'duration': 0.04,
            'payload_ratio': 0.04,
            'inter_arrival_time': 0.04,
            'ack_count': 0.03,
            'service_code': 0.03,
            'urgent_count': 0.02,
            'connection_state': 0.02,
        }

import numpy as np
import pandas as pd
from pathlib import Path
from typing import Tuple, Optional, List
import logging
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE, RandomOverSampler

logger = logging.getLogger(__name__)


class CICIDSLoader:
    """
    Loads and preprocesses CICIDS2017/2018 dataset.
    Supports both single-file (CICIDS2018) and multi-file (CICIDS2017 MachineLearningCVE) formats.
    """

    # CICIDS2018 labels
    ATTACK_TYPES_2018 = {
        'BENIGN': 0,
        'DoS attacks-Hulk': 1,
        'DoS attacks-SlowHTTPTest': 1,
        'DoS attacks-Slowloris': 1,
        'DoS attacks-GoldenEye': 1,
        'Brute Force -XSS': 2,
        'Brute Force -Web': 2,
        'SQL Injection': 3,
        'Infiltration': 4,
        'Bot': 4,
    }

    # CICIDS2017 (MachineLearningCVE) labels
    ATTACK_TYPES_2017 = {
        'BENIGN': 0,
        'DDoS': 1,
        'DoS Hulk': 1,
        'DoS GoldenEye': 1,
        'DoS slowloris': 1,
        'DoS Slowhttptest': 1,
        'Heartbleed': 1,
        'Web Attack \u2013 Brute Force': 2,
        'Web Attack \u2013 XSS': 2,
        'FTP-Patator': 2,
        'SSH-Patator': 2,
        'Web Attack \u2013 Sql Injection': 3,
        'Bot': 4,
        'Infiltration': 4,
        'PortScan': 4,
    }

    LABEL_NAMES = {
        0: 'benign',
        1: 'ddos',
        2: 'brute_force',
        3: 'sql_injection',
        4: 'anomaly',
    }

    # 50 key features selected from CICIDS2017's 78 columns
    CICIDS2017_SELECTED_FEATURES = [
        'Destination Port',
        'Flow Duration',
        'Total Fwd Packets',
        'Total Backward Packets',
        'Total Length of Fwd Packets',
        'Total Length of Bwd Packets',
        'Fwd Packet Length Max',
        'Fwd Packet Length Min',
        'Fwd Packet Length Mean',
        'Fwd Packet Length Std',
        'Bwd Packet Length Max',
        'Bwd Packet Length Min',
        'Bwd Packet Length Mean',
        'Bwd Packet Length Std',
        'Flow Bytes/s',
        'Flow Packets/s',
        'Flow IAT Mean',
        'Flow IAT Std',
        'Flow IAT Max',
        'Flow IAT Min',
        'Fwd IAT Total',
        'Fwd IAT Mean',
        'Fwd IAT Std',
        'Fwd IAT Max',
        'Fwd IAT Min',
        'Bwd IAT Total',
        'Bwd IAT Mean',
        'Bwd IAT Std',
        'Fwd PSH Flags',
        'Fwd URG Flags',
        'Fwd Header Length',
        'Bwd Header Length',
        'Fwd Packets/s',
        'Bwd Packets/s',
        'Min Packet Length',
        'Max Packet Length',
        'Packet Length Mean',
        'Packet Length Std',
        'Packet Length Variance',
        'FIN Flag Count',
        'SYN Flag Count',
        'RST Flag Count',
        'PSH Flag Count',
        'ACK Flag Count',
        'URG Flag Count',
        'Down/Up Ratio',
        'Average Packet Size',
        'Init_Win_bytes_forward',
        'Init_Win_bytes_backward',
        'Active Mean',
    ]

    def __init__(self, data_dir: str = 'ai/data/cicids2018'):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _detect_format(self) -> str:
        """Detect dataset format: '2018' for single CSV, '2017' for multi-file directory."""
        single_csv = self.data_dir / 'cicids2018.csv'
        if single_csv.exists():
            return '2018'
        csv_files = list(self.data_dir.glob('*.csv'))
        if csv_files:
            return '2017'
        raise FileNotFoundError(
            f"No dataset found in {self.data_dir}. "
            "Expected cicids2018.csv (CICIDS2018) or multiple .csv files (CICIDS2017)."
        )

    def _list_csv_files(self) -> List[Path]:
        """Return all CSV files sorted by name."""
        files = sorted(self.data_dir.glob('*.csv'))
        if not files:
            raise FileNotFoundError(f"No CSV files found in {self.data_dir}")
        return files

    def load_dataset(self, csv_file: str = 'cicids2018.csv',
                     sample_frac: float = 1.0) -> Tuple[pd.DataFrame, np.ndarray]:
        """
        Load dataset from CSV(s). Auto-detects CICIDS2017 multi-file format
        when the expected single file is missing.
        """
        csv_path = self.data_dir / csv_file

        if not csv_path.exists():
            # Try CICIDS2017 multi-file format
            csv_files = list(self.data_dir.glob('*.csv'))
            if not csv_files:
                logger.error(f"Dataset not found at {csv_path}")
                logger.info("Please download CICIDS2018 from: https://www.unb.ca/cic/datasets/ids-2018.html")
                raise FileNotFoundError(f"Dataset not found: {csv_path}")
            return self._load_cicids2017(csv_files, sample_frac)

        logger.info(f"Loading CICIDS2018 dataset from {csv_path}")
        df = pd.read_csv(csv_path)
        df.columns = df.columns.str.strip()
        logger.info(f"Loaded {len(df)} samples")

        if sample_frac < 1.0:
            df = df.sample(frac=sample_frac, random_state=42)
            logger.info(f"Sampled to {len(df)} samples")

        label_col = 'Label' if 'Label' in df.columns else df.columns[-1]
        labels = df[label_col].values
        y = np.array([self.ATTACK_TYPES_2018.get(str(lbl).strip(), 0) for lbl in labels])
        X_df = df.drop(columns=[label_col])
        return X_df, y

    def _load_cicids2017(self, csv_files: List[Path],
                         sample_frac: float = 1.0) -> Tuple[pd.DataFrame, np.ndarray]:
        """Load and combine all CICIDS2017 CSV files."""
        logger.info(f"Loading CICIDS2017 dataset from {len(csv_files)} files...")

        dfs = []
        for f in csv_files:
            logger.info(f"  Reading {f.name}  ({f.stat().st_size / 1e6:.1f} MB)")
            try:
                chunk = pd.read_csv(f, encoding='latin1', low_memory=False)
                chunk.columns = chunk.columns.str.strip()
                dfs.append(chunk)
            except Exception as e:
                logger.warning(f"  Failed to read {f.name}: {e}")

        if not dfs:
            raise ValueError("No CSV files could be loaded.")

        df = pd.concat(dfs, ignore_index=True)
        logger.info(f"Combined dataset: {len(df)} rows")

        if sample_frac < 1.0:
            df = df.sample(frac=sample_frac, random_state=42).reset_index(drop=True)
            logger.info(f"Sampled to {len(df)} rows")

        # Extract label
        label_col = 'Label'
        labels = df[label_col].values
        y = np.array([self.ATTACK_TYPES_2017.get(str(lbl).strip(), 0) for lbl in labels])

        logger.info("Label distribution in sample:")
        unique, counts = np.unique(y, return_counts=True)
        for lbl, cnt in zip(unique, counts):
            logger.info(f"  {self.LABEL_NAMES.get(lbl, lbl)}: {cnt}")

        # Select 50 features (keep only available ones)
        available = [c for c in self.CICIDS2017_SELECTED_FEATURES if c in df.columns]
        missing = [c for c in self.CICIDS2017_SELECTED_FEATURES if c not in df.columns]
        if missing:
            logger.warning(f"Missing {len(missing)} columns; padding with zeros: {missing}")

        X_df = df[available].copy()

        # Pad missing columns with zeros
        for col in missing:
            X_df[col] = 0.0

        # Reorder to standard order
        X_df = X_df[self.CICIDS2017_SELECTED_FEATURES]

        return X_df, y

    @staticmethod
    def clean_data(df: pd.DataFrame) -> pd.DataFrame:
        """Clean dataset: remove NaN, Inf, keep only numeric columns."""
        logger.info(f"Cleaning data: {len(df)} samples")
        df = df.dropna()
        df = df.replace([np.inf, -np.inf], 0)
        df = df.select_dtypes(include=[np.number])
        logger.info(f"After cleaning: {len(df)} samples")
        return df

    def load_and_preprocess(self, csv_file: str = 'cicids2018.csv',
                            sample_frac: float = 1.0,
                            test_size: float = 0.2,
                            apply_smote: bool = True) -> dict:
        """
        Complete preprocessing pipeline.
        Returns dict with X_train, X_test, y_train, y_test, label_distribution, normalization.
        """
        X_df, y = self.load_dataset(csv_file, sample_frac)

        # Keep label in df so that row alignment is preserved through dropna
        X_df = X_df.copy()
        X_df['__label__'] = y
        X_df = self.clean_data(X_df)
        y = X_df['__label__'].values.astype(np.int32)
        X_df = X_df.drop(columns=['__label__'])

        logger.info(f"Dataset has {X_df.shape[1]} features")

        # Use stratify only if all classes have enough samples for the split
        unique_cls, cls_counts = np.unique(y, return_counts=True)
        min_required = max(2, int(1.0 / test_size) + 1)
        can_stratify = bool(cls_counts.min() >= min_required)
        try:
            X_train, X_test, y_train, y_test = train_test_split(
                X_df.values, y, test_size=test_size, random_state=42,
                stratify=y if can_stratify else None
            )
        except ValueError:
            logger.warning("Stratified split failed, falling back to random split")
            X_train, X_test, y_train, y_test = train_test_split(
                X_df.values, y, test_size=test_size, random_state=42
            )
        logger.info(f"Train: {len(X_train)}, Test: {len(X_test)}")

        unique, counts = np.unique(y_train, return_counts=True)
        logger.info("Class distribution (before SMOTE):")
        for lbl, cnt in zip(unique, counts):
            logger.info(f"  {self.LABEL_NAMES.get(lbl, lbl)}: {cnt}")

        if apply_smote and len(np.unique(y_train)) > 1:
            try:
                unique_smote, counts_smote = np.unique(y_train, return_counts=True)
                min_class_size = int(counts_smote.min())
                max_class_size = int(counts_smote.max())

                # Cap target per class at 10 000 to avoid excessive data expansion
                target_per_class = min(max_class_size, 10_000)
                sampling_strategy = {
                    int(lbl): target_per_class
                    for lbl, cnt in zip(unique_smote, counts_smote)
                    if int(cnt) < target_per_class
                }

                if not sampling_strategy:
                    logger.info("No oversampling needed (all classes already at target size)")
                else:
                    # Try SMOTE first; fall back to RandomOverSampler on failure
                    try:
                        k = min(3, max(1, min_class_size - 1))
                        logger.info(
                            f"SMOTE target={target_per_class}/class, k_neighbors={k}"
                        )
                        resampler = SMOTE(random_state=42, k_neighbors=k,
                                          sampling_strategy=sampling_strategy)
                        X_train, y_train = resampler.fit_resample(X_train, y_train)
                    except Exception as smote_err:
                        logger.warning(f"SMOTE failed ({smote_err}), using RandomOverSampler")
                        resampler = RandomOverSampler(
                            sampling_strategy=sampling_strategy, random_state=42
                        )
                        X_train, y_train = resampler.fit_resample(X_train, y_train)

                    logger.info(f"Applied oversampling: {len(X_train)} train samples")
                    unique, counts = np.unique(y_train, return_counts=True)
                    logger.info("Class distribution (after oversampling):")
                    for lbl, cnt in zip(unique, counts):
                        logger.info(f"  {self.LABEL_NAMES.get(lbl, lbl)}: {cnt}")
            except Exception as e:
                logger.warning(f"Oversampling failed: {e}, continuing without balancing")

        mean = np.mean(X_train, axis=0)
        std = np.std(X_train, axis=0)
        std = np.where(std == 0, 1.0, std)

        X_train = (X_train - mean) / std
        X_test = (X_test - mean) / std

        X_train = np.nan_to_num(X_train, nan=0.0, posinf=0.0, neginf=0.0)
        X_test = np.nan_to_num(X_test, nan=0.0, posinf=0.0, neginf=0.0)

        unique_final, counts_final = np.unique(y_train, return_counts=True)
        label_dist = {
            self.LABEL_NAMES.get(int(lbl), f'class_{lbl}'): int(cnt)
            for lbl, cnt in zip(unique_final, counts_final)
        }

        return {
            'X_train': X_train.astype(np.float32),
            'X_test': X_test.astype(np.float32),
            'y_train': y_train.astype(np.int32),
            'y_test': y_test.astype(np.int32),
            'label_distribution': label_dist,
            'normalization': {
                'mean': mean.astype(np.float32),
                'std': std.astype(np.float32),
            }
        }

    @staticmethod
    def create_sequences(X: np.ndarray, y: np.ndarray = None,
                         seq_length: int = 10) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """
        Create sequences for LSTM.
        Input:  (n_samples, n_features)
        Output: (n_samples - seq_length, seq_length, n_features)
        """
        X_seq, y_seq = [], []
        for i in range(len(X) - seq_length):
            X_seq.append(X[i:i + seq_length])
            if y is not None:
                y_seq.append(y[i + seq_length])

        X_seq = np.array(X_seq, dtype=np.float32)
        y_seq = np.array(y_seq, dtype=np.int32) if y is not None else None
        return X_seq, y_seq

    def get_sample_for_inference(self) -> np.ndarray:
        """Return a random sample feature vector for testing inference."""
        return np.random.randn(50).astype(np.float32)

    @staticmethod
    def get_attack_type_name(label_id: int) -> str:
        return CICIDSLoader.LABEL_NAMES.get(label_id, 'unknown')

    @staticmethod
    def get_attack_type_id(label_name: str) -> int:
        for name, id_ in CICIDSLoader.LABEL_NAMES.items():
            if id_ == label_name:
                return name
        return 0

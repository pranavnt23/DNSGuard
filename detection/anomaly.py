"""
Machine Learning Anomaly Detection Module for DNSGuard.

Uses Scikit-learn's Isolation Forest to profile baseline legitimate DNS activity
and quantify behavioral outliers without relying solely on static signatures.

Academic & Operational Notice:
    "Anomaly detection identifies behaviour that differs statistically from the baseline;
    it does not automatically prove that traffic is malicious."
    Outlier scores serve as an evidentiary factor in the multi-tier risk framework.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from backend.logging_config import get_logger
from database.models import DetectionType
from detection.rules import DetectionConfig, DetectorVerdict

logger = get_logger("anomaly_ml")

DEFAULT_MODEL_PATH = "./models/isolation_forest.joblib"

# 10 canonical numeric feature dimensions
FEATURE_COLUMNS = [
    "domain_length",
    "subdomain_count",
    "entropy",
    "vowel_ratio",
    "digit_ratio",
    "max_consonant_sequence",
    "query_type_code",
    "ttl_value",
    "packet_size",
    "query_rate_per_sec",
]


def extract_numeric_feature_vector(features: Dict[str, Any]) -> List[float]:
    """
    Extracts and imputes the ordered numeric feature vector for Scikit-learn models.

    Args:
        features: Dictionary of extracted DNS features.

    Returns:
        List[float]: 10-dimensional numeric vector.
    """
    ttl_val = features.get("ttl_value") if features.get("ttl_value") is not None else features.get("ttl")
    imputed_ttl = float(ttl_val) if ttl_val is not None else 300.0

    return [
        float(features.get("domain_length") or len(features.get("domain", ""))),
        float(features.get("subdomain_count") or features.get("subdomain_depth") or 0),
        float(features.get("entropy") or features.get("shannon_entropy") or 0.0),
        float(features.get("vowel_ratio") if features.get("vowel_ratio") is not None else 0.4),
        float(features.get("digit_ratio") or 0.0),
        float(features.get("max_consonant_sequence") or 0),
        float(features.get("query_type_code") or 1),
        imputed_ttl,
        float(features.get("packet_size") or features.get("packet_length") or 64),
        float(features.get("query_rate_per_sec") or features.get("client_query_rate_per_sec") or 0.0),
    ]


class IsolationForestDetector:
    """
    Lightweight, explainable unsupervised anomaly detector powered by Isolation Forest.
    """

    def __init__(
        self,
        config: Optional[DetectionConfig] = None,
        model_path: str = DEFAULT_MODEL_PATH,
    ):
        self.config = config or DetectionConfig()
        self.model_path = model_path
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.is_trained: bool = False
        self.trained_at: Optional[str] = None
        self.feature_names = FEATURE_COLUMNS

        # Attempt to auto-load saved model if available on disk
        self._try_load()

    def _try_load(self) -> bool:
        """Attempts to load a pre-trained model bundle from disk."""
        path = Path(self.model_path)
        if path.exists():
            try:
                bundle = joblib.load(str(path))
                self.model = bundle["model"]
                self.scaler = bundle["scaler"]
                self.is_trained = True
                self.trained_at = bundle.get("trained_at")
                logger.info("Loaded trained Isolation Forest anomaly model from: %s", path)
                return True
            except Exception as exc:
                logger.warning("Could not load model at %s: %s", path, exc)
        return False

    def fit(
        self,
        baseline_dataset: List[Dict[str, Any]],
        contamination: Optional[float] = None,
        random_state: int = 42,
    ) -> Dict[str, Any]:
        """
        Trains the Isolation Forest model on baseline normal events.

        Args:
            baseline_dataset: List of feature dictionaries representing normal traffic.
            contamination: Expected anomaly ratio (default from config: 0.10).
            random_state: Fixed random seed for reproducibility.

        Returns:
            Dict[str, Any]: Training summary metrics.
        """
        if not baseline_dataset:
            raise ValueError("Baseline dataset for training must not be empty.")

        X_raw = np.array([extract_numeric_feature_vector(item) for item in baseline_dataset])

        # Preprocessing: StandardScaler
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_raw)

        contam = contamination if contamination is not None else self.config.anomaly_contamination
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contam,
            random_state=random_state,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)

        self.is_trained = True
        self.trained_at = datetime.now(timezone.utc).isoformat()
        logger.info("Trained Isolation Forest on %d sample records", len(baseline_dataset))

        return {
            "sample_count": len(baseline_dataset),
            "features_used": self.feature_names,
            "contamination": contam,
            "trained_at": self.trained_at,
        }

    def save(self, path: Optional[str] = None) -> str:
        """Saves model and scaler pipeline to disk."""
        if not self.is_trained or self.model is None or self.scaler is None:
            raise RuntimeError("Cannot save model: detector has not been trained yet.")

        target = Path(path or self.model_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        bundle = {
            "model": self.model,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "trained_at": self.trained_at,
        }
        joblib.dump(bundle, str(target))
        logger.info("Saved Isolation Forest model pipeline to: %s", target)
        return str(target)

    def evaluate(self, features: Dict[str, Any]) -> DetectorVerdict:
        """
        Scores a DNS event and returns an explainable anomaly verdict.

        Args:
            features: Dictionary of extracted DNS features.

        Returns:
            DetectorVerdict: Model verdict with anomaly score (0 - 100).
        """
        # Fallback: if not trained, auto-fit on standard synthetic baseline
        if not self.is_trained or self.model is None or self.scaler is None:
            self._fit_default_baseline()

        vec = np.array([extract_numeric_feature_vector(features)])
        vec_scaled = self.scaler.transform(vec)

        # IsolationForest decision_function: lower score = more anomalous
        # Typical range: -0.3 (extreme outlier) to +0.25 (deep inliner)
        raw_score = float(self.model.decision_function(vec_scaled)[0])
        pred = int(self.model.predict(vec_scaled)[0])  # -1 = anomaly, 1 = normal

        # Normalize to 0 - 100 range:
        # A raw_score >= 0.15 maps to ~ 0.0 (very normal)
        # A raw_score <= -0.15 maps to ~ 100.0 (high anomaly)
        # Formula: normalized = clip((0.15 - raw_score) / 0.30 * 100, 0, 100)
        norm_score = float(np.clip((0.15 - raw_score) / 0.30 * 100.0, 0.0, 100.0))
        norm_score = round(norm_score, 2)

        is_suspicious = bool(pred == -1 or norm_score >= 60.0)
        confidence = round(min(0.92, max(0.40, norm_score / 100.0)), 2)

        evidence = []
        if is_suspicious:
            evidence.append(f"Statistical isolation outlier (score={norm_score}/100, raw={raw_score:.3f})")
            narrative = f"Machine learning anomaly detected: Traffic feature profile deviates from normal baseline (anomaly score: {norm_score}/100)."
        else:
            narrative = f"Normal profile: Traffic features align with legitimate baseline (anomaly score: {norm_score}/100)."

        return DetectorVerdict(
            threat_type=DetectionType.ANOMALY_ML,
            is_suspicious=is_suspicious,
            score=norm_score,
            confidence=confidence,
            evidence=evidence,
            reason=narrative,
            model_or_rule="Model:IsolationForest_v1",
            details={
                "raw_decision_score": round(raw_score, 4),
                "is_outlier": is_suspicious,
                "vector": vec[0].tolist(),
                "feature_names": self.feature_names,
            },
        )

    def _fit_default_baseline(self) -> None:
        """Trains on default synthetic benign sample records if no external model exists."""
        from dns_engine.sample_data import generate_sample_dataset
        from dns_engine.features import extract_features

        logger.info("Initializing baseline model using synthetic normal samples...")
        samples = generate_sample_dataset()
        benign_features = []

        for item in samples:
            # Train only on benign samples to avoid data contamination
            if "benign" in str(item.get("synthetic_label", "")):
                _, details = extract_features(
                    domain=item["domain"],
                    query_type=item["query_type"],
                    response_code=item.get("response_code", "NOERROR"),
                    response_data=item.get("response_data", []),
                    ttl=item.get("ttl", 300),
                    packet_length=item.get("packet_length", 64),
                )
                benign_features.append(details)

        if len(benign_features) < 5:
            # Add basic synthetic benign defaults to ensure sufficient rows for scaler
            for d in ["example.com", "mycompany.org", "internal.corp", "api.github.com", "cdn.google.com"]:
                _, details = extract_features(domain=d, query_type="A", ttl=300)
                benign_features.append(details)

        self.fit(benign_features, contamination=0.10)

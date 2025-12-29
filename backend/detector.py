# backend/detector.py

import time
import joblib
import numpy as np
from typing import Dict


class ThreatDetector:
    """
    STRICT ML-BASED ransomware detector.
    No heuristics. No fallback scoring.
    If ML fails, system enters DEGRADED mode.
    """

    FEATURE_ORDER = [
    "cpu_percent", "memory_percent", "threads", "uptime", "cpu_spike_count",
    "file_writes", "file_reads", "file_deletes", "file_renames", "file_modifications",
    "extension_changes", "entropy_mean", "entropy_variance", "entropy_max",
    "high_entropy_file_ratio", "rapid_file_ops_count", "mass_file_change_events",
    "suspicious_extensions_count", "network_connections", "outbound_data_kb",
    "read_write_delete_pattern", "process_injection_attempts"
]


    def __init__(self, model_path: str = "ml_model/models/lightgbm_model_v2.0.pkl",
                 scaler_path: str = "ml_model/models/lightgbm_scaler_v2.0.pkl"):

        self.model = None
        self.scaler = None
        self.model_loaded = False
        self.model_version = "2.0"
        self.load_error = None

        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.model_loaded = True
        except Exception as e:
            self.load_error = str(e)
            self.model_loaded = False

    def analyze_features(self, analysis: Dict) -> Dict:
        """
        Perform ML inference on extracted features.
        """

        result = {
            "timestamp": time.time(),
            "status": "OK",
            "decision": "UNDETERMINED",
            "probability": None,
            "threat_level": None,
            "reason": None,
        }

        # --- Model availability check ---
        if not self.model_loaded:
            result.update({
                "status": "DEGRADED",
                "decision": "UNAVAILABLE",
                "reason": f"ML model not loaded: {self.load_error}"
            })
            return result

        # --- Input validation ---
        if not analysis.get("valid", False):
            result.update({
                "status": "INVALID",
                "decision": "UNAVAILABLE",
                "reason": analysis.get("reason", "Invalid feature set")
            })
            return result

        features = analysis.get("features")
        if not isinstance(features, dict):
            result.update({
                "status": "INVALID",
                "decision": "UNAVAILABLE",
                "reason": "Features missing or malformed"
            })
            return result

        # --- Feature order enforcement ---
        try:
            feature_vector = []
            for key in self.FEATURE_ORDER:
                if key not in features:
                    raise KeyError(f"Missing feature: {key}")
                feature_vector.append(float(features[key]))

            X = np.array(feature_vector).reshape(1, -1)
            X_scaled = self.scaler.transform(X)

            probability = float(self.model.predict_proba(X_scaled)[0][1])
            result["probability"] = probability

        except Exception as e:
            result.update({
                "status": "ERROR",
                "decision": "UNAVAILABLE",
                "reason": f"Inference failure: {str(e)}"
            })
            return result

        # --- Decision policy (ONLY HERE) ---
        if probability < 0.30:
            result["decision"] = "SAFE"
            result["threat_level"] = "NONE"
        elif probability < 0.60:
            result["decision"] = "SUSPICIOUS"
            result["threat_level"] = "MEDIUM"
        else:
            result["decision"] = "RANSOMWARE"
            result["threat_level"] = "HIGH"

        return result

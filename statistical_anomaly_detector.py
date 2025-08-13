#!/usr/bin/env python3
"""
Advanced Statistical Anomaly Detection Module
Based on Imperial College streaming analytics and time-series analysis research
"""

import numpy as np
import pandas as pd
from scipy import stats
from typing import Dict, List, Tuple, Optional, Union
from dataclasses import dataclass
import time
import logging
from collections import deque
import json
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

@dataclass
class TimeSeriesPoint:
    timestamp: float
    value: float
    feature_name: str
    metadata: Dict = None

@dataclass
class AnomalyAlert:
    timestamp: float
    anomaly_type: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    score: float
    affected_features: List[str]
    description: str
    metadata: Dict = None

class AdaptiveThresholdDetector:
    """
    Adaptive threshold detector using exponential moving averages
    Based on Imperial College adaptive streaming methods
    """

    def __init__(self, window_size: int = 100, alpha: float = 0.1, 
                 sensitivity: float = 2.0):
        self.window_size = window_size
        self.alpha = alpha  # Forgetting factor
        self.sensitivity = sensitivity  # Standard deviation multiplier

        # State variables
        self.mean = 0.0
        self.variance = 1.0
        self.count = 0
        self.history = deque(maxlen=window_size)

    def update(self, value: float) -> Tuple[bool, float]:
        """
        Update the adaptive threshold and check for anomaly
        Returns: (is_anomaly, anomaly_score)
        """
        self.history.append(value)

        if self.count == 0:
            self.mean = value
            self.variance = 1.0
        else:
            # Exponential moving average for mean
            delta = value - self.mean
            self.mean += self.alpha * delta

            # Exponential moving average for variance
            self.variance = (1 - self.alpha) * self.variance + self.alpha * (delta ** 2)

        self.count += 1

        # Calculate anomaly score
        if self.variance > 0:
            std_dev = np.sqrt(self.variance)
            z_score = abs(value - self.mean) / std_dev
            is_anomaly = z_score > self.sensitivity
            anomaly_score = z_score / self.sensitivity
        else:
            z_score = 0
            is_anomaly = False
            anomaly_score = 0.0

        return is_anomaly, min(1.0, anomaly_score)

    def get_threshold(self) -> Tuple[float, float]:
        """Get current upper and lower thresholds"""
        std_dev = np.sqrt(self.variance)
        upper = self.mean + self.sensitivity * std_dev
        lower = self.mean - self.sensitivity * std_dev
        return upper, lower

class ChangePointDetector:
    """
    Online change point detection using CUSUM algorithm
    """

    def __init__(self, threshold: float = 5.0, drift: float = 0.5):
        self.threshold = threshold
        self.drift = drift
        self.cusum_pos = 0.0
        self.cusum_neg = 0.0
        self.baseline_mean = 0.0
        self.baseline_std = 1.0
        self.samples = deque(maxlen=100)

    def update(self, value: float) -> Tuple[bool, str]:
        """
        Update CUSUM and detect change points
        Returns: (change_detected, change_type)
        """
        self.samples.append(value)

        # Update baseline statistics
        if len(self.samples) >= 30:
            recent_samples = list(self.samples)[-30:]
            self.baseline_mean = np.mean(recent_samples)
            self.baseline_std = np.std(recent_samples)

        if self.baseline_std == 0:
            return False, "none"

        # Standardize the value
        standardized = (value - self.baseline_mean) / self.baseline_std

        # Update CUSUM statistics
        self.cusum_pos = max(0, self.cusum_pos + standardized - self.drift)
        self.cusum_neg = max(0, self.cusum_neg - standardized - self.drift)

        # Check for change points
        if self.cusum_pos > self.threshold:
            self.cusum_pos = 0  # Reset
            return True, "upward"
        elif self.cusum_neg > self.threshold:
            self.cusum_neg = 0  # Reset
            return True, "downward"

        return False, "none"

class MultivariateAnomalyDetector:
    """
    Multivariate anomaly detection using robust covariance estimation
    """

    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self.detector = EllipticEnvelope(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.feature_names = []

    def fit(self, X: np.ndarray, feature_names: List[str] = None):
        """Fit the multivariate detector"""
        X_scaled = self.scaler.fit_transform(X)
        self.detector.fit(X_scaled)
        self.is_fitted = True
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X.shape[1])]

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies
        Returns: (anomaly_labels, anomaly_scores)
        """
        if not self.is_fitted:
            raise ValueError("Detector must be fitted before prediction")

        X_scaled = self.scaler.transform(X)
        anomaly_labels = self.detector.predict(X_scaled)
        anomaly_scores = self.detector.score_samples(X_scaled)

        # Convert sklearn format (-1 for anomaly, 1 for normal) to boolean
        is_anomaly = anomaly_labels == -1

        return is_anomaly, -anomaly_scores  # Negate scores for intuitive interpretation

class ConceptDriftDetector:
    """
    Detect concept drift in data streams using Page-Hinkley test
    """

    def __init__(self, delta: float = 0.005, threshold: float = 50.0):
        self.delta = delta  # Allowed variation
        self.threshold = threshold  # Drift threshold
        self.mean = 0.0
        self.ph_sum = 0.0
        self.ph_min = 0.0
        self.count = 0

    def update(self, value: float) -> bool:
        """
        Update detector and check for concept drift
        Returns: True if drift detected
        """
        if self.count == 0:
            self.mean = value
        else:
            # Update mean incrementally
            self.mean = (self.mean * self.count + value) / (self.count + 1)

        self.count += 1

        # Page-Hinkley test
        self.ph_sum += value - self.mean - self.delta
        self.ph_min = min(self.ph_min, self.ph_sum)

        # Check for drift
        drift_detected = (self.ph_sum - self.ph_min) > self.threshold

        if drift_detected:
            # Reset after detecting drift
            self.ph_sum = 0.0
            self.ph_min = 0.0

        return drift_detected

class StatisticalAnomalyEngine:
    """
    Main statistical anomaly detection engine combining multiple methods
    """

    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Initialize detectors
        self.adaptive_detectors = {}  # Per-feature adaptive threshold detectors
        self.change_point_detectors = {}  # Per-feature change point detectors
        self.concept_drift_detector = ConceptDriftDetector(
            delta=config.get('drift_delta', 0.005),
            threshold=config.get('drift_threshold', 50.0)
        )

        # Multivariate detector
        self.multivariate_detector = MultivariateAnomalyDetector(
            contamination=config.get('contamination', 0.1)
        )

        # Alert management
        self.alert_history = deque(maxlen=1000)
        self.alert_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}

        # Feature tracking
        self.feature_buffer = {}
        self.buffer_size = config.get('buffer_size', 1000)

    def add_observation(self, timestamp: float, features: Dict[str, float]) -> List[AnomalyAlert]:
        """
        Add new observation and detect anomalies
        Returns list of anomaly alerts
        """
        alerts = []

        # Process each feature individually
        for feature_name, value in features.items():
            feature_alerts = self._process_feature(timestamp, feature_name, value)
            alerts.extend(feature_alerts)

        # Multivariate analysis
        multivariate_alerts = self._process_multivariate(timestamp, features)
        alerts.extend(multivariate_alerts)

        # Concept drift detection on overall activity
        overall_activity = sum(features.values()) / len(features)
        drift_detected = self.concept_drift_detector.update(overall_activity)
        if drift_detected:
            alert = AnomalyAlert(
                timestamp=timestamp,
                anomaly_type="concept_drift",
                severity="medium",
                score=0.8,
                affected_features=list(features.keys()),
                description="Concept drift detected in overall network behavior",
                metadata={"overall_activity": overall_activity}
            )
            alerts.append(alert)

        # Store alerts
        for alert in alerts:
            self.alert_history.append(alert)
            self.alert_counts[alert.severity] += 1

        return alerts

    def _process_feature(self, timestamp: float, feature_name: str, value: float) -> List[AnomalyAlert]:
        """Process individual feature for anomalies"""
        alerts = []

        # Initialize detectors for new features
        if feature_name not in self.adaptive_detectors:
            self.adaptive_detectors[feature_name] = AdaptiveThresholdDetector(
                sensitivity=self.config.get('sensitivity', 2.0)
            )
            self.change_point_detectors[feature_name] = ChangePointDetector(
                threshold=self.config.get('change_threshold', 5.0)
            )
            self.feature_buffer[feature_name] = deque(maxlen=self.buffer_size)

        # Store observation
        self.feature_buffer[feature_name].append(TimeSeriesPoint(
            timestamp=timestamp,
            value=value,
            feature_name=feature_name
        ))

        # Adaptive threshold detection
        is_anomaly, anomaly_score = self.adaptive_detectors[feature_name].update(value)
        if is_anomaly:
            severity = self._calculate_severity(anomaly_score)
            alert = AnomalyAlert(
                timestamp=timestamp,
                anomaly_type="threshold_breach",
                severity=severity,
                score=anomaly_score,
                affected_features=[feature_name],
                description=f"Adaptive threshold breach in {feature_name}",
                metadata={"value": value, "feature": feature_name}
            )
            alerts.append(alert)

        # Change point detection
        change_detected, change_type = self.change_point_detectors[feature_name].update(value)
        if change_detected:
            alert = AnomalyAlert(
                timestamp=timestamp,
                anomaly_type="change_point",
                severity="medium",
                score=0.7,
                affected_features=[feature_name],
                description=f"Change point detected in {feature_name} ({change_type})",
                metadata={"change_type": change_type, "feature": feature_name}
            )
            alerts.append(alert)

        return alerts

    def _process_multivariate(self, timestamp: float, features: Dict[str, float]) -> List[AnomalyAlert]:
        """Process multivariate anomalies"""
        alerts = []

        # Convert to array
        feature_names = sorted(features.keys())
        feature_vector = np.array([features[name] for name in feature_names]).reshape(1, -1)

        # Check if detector is fitted
        if not self.multivariate_detector.is_fitted:
            # Collect samples to fit detector
            if not hasattr(self, '_multivariate_buffer'):
                self._multivariate_buffer = []
                self._multivariate_feature_names = feature_names

            self._multivariate_buffer.append(feature_vector[0])

            # Fit when we have enough samples
            if len(self._multivariate_buffer) >= 50:
                X = np.array(self._multivariate_buffer)
                self.multivariate_detector.fit(X, self._multivariate_feature_names)
                self.logger.info("Multivariate detector fitted with initial samples")
        else:
            # Predict anomaly
            try:
                is_anomaly, anomaly_scores = self.multivariate_detector.predict(feature_vector)

                if is_anomaly[0]:
                    severity = self._calculate_severity(anomaly_scores[0])
                    alert = AnomalyAlert(
                        timestamp=timestamp,
                        anomaly_type="multivariate_anomaly",
                        severity=severity,
                        score=float(anomaly_scores[0]),
                        affected_features=feature_names,
                        description="Multivariate anomaly detected across multiple features",
                        metadata={"feature_scores": dict(zip(feature_names, feature_vector[0]))}
                    )
                    alerts.append(alert)
            except Exception as e:
                self.logger.warning(f"Multivariate detection failed: {e}")

        return alerts

    def _calculate_severity(self, score: float) -> str:
        """Calculate severity based on anomaly score"""
        if score >= 0.9:
            return "critical"
        elif score >= 0.7:
            return "high"
        elif score >= 0.5:
            return "medium"
        else:
            return "low"

    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        total_alerts = sum(self.alert_counts.values())

        feature_stats = {}
        for feature_name, detector in self.adaptive_detectors.items():
            upper, lower = detector.get_threshold()
            feature_stats[feature_name] = {
                "current_mean": detector.mean,
                "current_variance": detector.variance,
                "upper_threshold": upper,
                "lower_threshold": lower,
                "sample_count": detector.count
            }

        return {
            "total_alerts": total_alerts,
            "alert_distribution": dict(self.alert_counts),
            "features_monitored": len(self.adaptive_detectors),
            "multivariate_fitted": self.multivariate_detector.is_fitted,
            "feature_statistics": feature_stats,
            "recent_alerts": len([a for a in self.alert_history if time.time() - a.timestamp < 3600])
        }

    def get_recent_alerts(self, hours: int = 1) -> List[AnomalyAlert]:
        """Get alerts from the last N hours"""
        cutoff_time = time.time() - (hours * 3600)
        return [alert for alert in self.alert_history if alert.timestamp >= cutoff_time]

if __name__ == "__main__":
    # Test the statistical anomaly engine
    import random
    import matplotlib.pyplot as plt

    config = {
        'sensitivity': 2.0,
        'contamination': 0.1,
        'buffer_size': 1000,
        'change_threshold': 5.0,
        'drift_threshold': 50.0
    }

    engine = StatisticalAnomalyEngine(config)

    # Generate synthetic network data with anomalies
    timestamps = []
    packet_rates = []
    bandwidth_usage = []
    connection_counts = []
    all_alerts = []

    print("Generating synthetic network traffic with anomalies...")

    for i in range(500):
        timestamp = time.time() + i

        # Normal traffic with some noise
        base_packet_rate = 100 + 20 * np.sin(i / 50) + random.gauss(0, 10)
        base_bandwidth = 1000000 + 200000 * np.sin(i / 30) + random.gauss(0, 50000)
        base_connections = 20 + 5 * np.sin(i / 40) + random.gauss(0, 2)

        # Inject anomalies
        if i == 200:  # Sudden spike (DDoS simulation)
            base_packet_rate *= 10
            base_bandwidth *= 5
            base_connections *= 3
        elif 300 <= i <= 320:  # Sustained anomaly
            base_packet_rate *= 2
            base_bandwidth *= 1.5
        elif i == 400:  # Port scan simulation
            base_connections *= 5
            base_packet_rate *= 1.5

        features = {
            "packet_rate": max(0, base_packet_rate),
            "bandwidth_usage": max(0, base_bandwidth),
            "connection_count": max(0, base_connections)
        }

        # Process with anomaly engine
        alerts = engine.add_observation(timestamp, features)

        # Store for visualization
        timestamps.append(timestamp)
        packet_rates.append(features["packet_rate"])
        bandwidth_usage.append(features["bandwidth_usage"])
        connection_counts.append(features["connection_count"])
        all_alerts.extend(alerts)

    print(f"\n✅ Processed 500 time points")
    print(f"📊 Total anomalies detected: {len(all_alerts)}")

    # Print statistics
    stats = engine.get_statistics()
    print(f"📈 Detection statistics:")
    print(json.dumps(stats, indent=2, default=str))

    # Print recent alerts
    recent_alerts = engine.get_recent_alerts(hours=24)  # All alerts in test
    print(f"\n🚨 Recent alerts by severity:")
    severity_counts = {}
    for alert in recent_alerts:
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
    print(json.dumps(severity_counts, indent=2))

    # Show sample alerts
    print(f"\n📋 Sample anomaly alerts:")
    for alert in recent_alerts[:5]:
        print(f"  - {alert.anomaly_type}: {alert.description} (severity: {alert.severity}, score: {alert.score:.3f})")
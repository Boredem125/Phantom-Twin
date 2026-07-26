"""
detector.py — Isolation Forest + per-entity z-score anomaly detector.

Computes 6 behavioral deviation features per event against the entity's profile,
combines with an Isolation Forest score into a composite risk score (0–100).

Usage:
    # Training the shared Isolation Forest:
    from backend.models.detector import train_isolation_forest
    train_isolation_forest("backend/data/train.csv")

    # Scoring a single event:
    from backend.models.detector import score_event, load_model
    model = load_model()
    result = score_event(event_dict, profile_dict, model)
"""

import logging
import math
import os
import pickle
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("detector")

MODEL_PATH = "backend/models/iso_forest.pkl"
SCALER_PATH = "backend/models/scaler.pkl"

RISK_THRESHOLDS = {
    "LOW": 40,
    "MEDIUM": 70,
    "HIGH": 85,
    "CRITICAL": 100,
}

FEATURE_WEIGHTS = {
    "hour_deviation": 0.20,
    "geo_deviation": 0.25,
    "resource_novelty": 0.20,
    "session_duration_z": 0.10,
    "auth_method_change": 0.15,
    "fingerprint_mismatch": 0.10,
}

GEO_COORDS: dict[str, tuple[float, float]] = {
    "Mumbai": (19.076, 72.877), "Delhi": (28.613, 77.209),
    "Bangalore": (12.971, 77.594), "Chennai": (13.083, 80.270),
    "Hyderabad": (17.385, 78.486), "London": (51.507, -0.128),
    "Berlin": (52.520, 13.405), "Paris": (48.857, 2.347),
    "Amsterdam": (52.370, 4.895), "Zurich": (47.377, 8.540),
    "New York": (40.713, -74.006), "Chicago": (41.879, -87.624),
    "Dallas": (32.779, -96.808), "San Francisco": (37.775, -122.418),
    "Seattle": (47.608, -122.335), "Singapore": (1.352, 103.820),
    "Tokyo": (35.689, 139.692), "Sydney": (-33.868, 151.207),
    "Dubai": (25.205, 55.271), "Toronto": (43.651, -79.383),
    "Unknown": (0.0, 0.0),
}


# ── Feature extraction ─────────────────────────────────────────────────────────

def haversine_km(geo_a: str, geo_b: str) -> float:
    """Great-circle distance between two named locations in km."""
    if geo_a not in GEO_COORDS or geo_b not in GEO_COORDS:
        return 0.0
    lat1, lon1 = GEO_COORDS[geo_a]
    lat2, lon2 = GEO_COORDS[geo_b]
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2
         + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2)
    return 2 * R * math.asin(math.sqrt(a))


def extract_features(event: dict[str, Any], profile: dict[str, Any]) -> dict[str, float]:
    """
    Compute 6 normalised deviation features for a single event vs entity profile.

    Returns a dict with keys matching FEATURE_WEIGHTS.
    """
    features: dict[str, float] = {}

    # 1. Hour deviation (z-score, clamped to [0, 5])
    try:
        ts = pd.to_datetime(event["timestamp"])
        event_hour = float(ts.hour + ts.minute / 60.0)
    except Exception:
        event_hour = 12.0
    peak_hour = float(profile.get("peak_hour", 12.0))
    hour_sigma = max(float(profile.get("hour_sigma", 1.5)), 0.1)
    hour_dev = abs(event_hour - peak_hour) / hour_sigma
    # Handle circular hour wrap-around
    wrapped = abs(event_hour - peak_hour + 24) / hour_sigma
    hour_dev = min(hour_dev, wrapped)
    features["hour_deviation"] = min(float(hour_dev), 5.0) / 5.0

    # 2. Geo deviation (0 = known geo, 0.5 = unknown geo, 1 = far unknown geo)
    event_geo = str(event.get("geo_location", "Unknown"))
    home_geos: list[str] = profile.get("home_geos", [])
    if event_geo in home_geos:
        geo_dev = 0.0
    else:
        primary_geo = max(profile.get("geo_weights", {}).items(), key=lambda x: x[1])[0] if profile.get("geo_weights") else "Unknown"
        dist = haversine_km(primary_geo, event_geo)
        geo_dev = min(dist / 15000.0 + 0.3, 1.0)  # 0.3 base for unknown + distance scaling
    features["geo_deviation"] = float(geo_dev)

    # 3. Resource novelty (fraction of accessed resource not in entity's top-20)
    resource = str(event.get("resource_accessed", ""))
    normal_resources: list[str] = profile.get("normal_resources", [])
    top20 = set(normal_resources[:20])
    features["resource_novelty"] = 0.0 if resource in top20 else 1.0

    # 4. Session duration z-score (clamped)
    try:
        duration = float(event.get("session_duration", 15.0))
    except (ValueError, TypeError):
        duration = 15.0
    avg_dur = max(float(profile.get("avg_duration", 15.0)), 0.1)
    dur_sigma = max(float(profile.get("dur_sigma", 5.0)), 0.1)
    dur_z = abs(duration - avg_dur) / dur_sigma
    features["session_duration_z"] = min(float(dur_z), 5.0) / 5.0

    # 5. Auth method change (0 = expected, 1 = changed)
    event_auth = str(event.get("auth_method", ""))
    preferred_auth = str(profile.get("preferred_auth", ""))
    features["auth_method_change"] = 0.0 if event_auth == preferred_auth else 1.0

    # 6. Fingerprint mismatch (0 = known, 1 = unknown)
    event_fp = str(event.get("device_fingerprint", ""))
    known_fps: list[str] = profile.get("known_fingerprints", [])
    features["fingerprint_mismatch"] = 0.0 if event_fp in known_fps else 1.0

    return features


def features_to_vector(features: dict[str, float]) -> np.ndarray:
    """Convert feature dict to numpy array in consistent order."""
    return np.array([features[k] for k in sorted(FEATURE_WEIGHTS.keys())], dtype=np.float64)


# ── Isolation Forest training ──────────────────────────────────────────────────

def train_isolation_forest(
    train_csv: str,
    model_path: str = MODEL_PATH,
    scaler_path: str = SCALER_PATH,
    profiles_dir: str = "backend/data/profiles",
) -> None:
    """Train a shared Isolation Forest on z-score feature vectors from train.csv."""
    from backend.models.profiler import load_profile  # local import to avoid circular

    logger.info("Loading training data from %s…", train_csv)
    df = pd.read_csv(train_csv)
    logger.info("Building feature vectors for %d events…", len(df))

    vectors: list[np.ndarray] = []
    for _, row in df.iterrows():
        event = row.to_dict()
        profile = load_profile(str(event["entity_id"]), str(event.get("entity_type", "user")), profiles_dir)
        feats = extract_features(event, profile)
        vectors.append(features_to_vector(feats))

    X = np.vstack(vectors)
    logger.info("Feature matrix shape: %s", X.shape)

    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    iso_forest = IsolationForest(
        n_estimators=200,
        contamination=0.02,
        random_state=42,
        n_jobs=-1,
    )
    iso_forest.fit(X_scaled)
    logger.info("Isolation Forest trained.")

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    with open(model_path, "wb") as f:
        pickle.dump(iso_forest, f)
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
    logger.info("Model saved to %s.", model_path)


def load_model(
    model_path: str = MODEL_PATH,
    scaler_path: str = SCALER_PATH,
) -> tuple[IsolationForest, MinMaxScaler]:
    """Load the trained Isolation Forest and scaler from disk."""
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found at {model_path}. Run train_isolation_forest first.")
    with open(model_path, "rb") as f:
        iso_forest: IsolationForest = pickle.load(f)
    with open(scaler_path, "rb") as f:
        scaler: MinMaxScaler = pickle.load(f)
    return iso_forest, scaler


# ── Risk scoring ───────────────────────────────────────────────────────────────

def compute_weighted_z_score(features: dict[str, float]) -> float:
    """Compute weighted composite deviation score (0–1)."""
    return sum(features[k] * FEATURE_WEIGHTS[k] for k in FEATURE_WEIGHTS)


def risk_level(score: float) -> str:
    """Return risk level label for a 0–100 composite score."""
    if score >= 85:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def score_event(
    event: dict[str, Any],
    profile: dict[str, Any],
    model: tuple[IsolationForest, MinMaxScaler] | None = None,
) -> dict[str, Any]:
    """
    Score a single event against its entity's profile.

    Returns:
        risk_score: float in [0, 100]
        risk_level: str (LOW | MEDIUM | HIGH | CRITICAL)
        feature_deviations: dict of per-feature scores
    """
    features = extract_features(event, profile)
    feat_vector = features_to_vector(features).reshape(1, -1)

    if model is not None:
        iso_forest, scaler = model
        try:
            X_scaled = scaler.transform(feat_vector)
            iso_raw = iso_forest.score_samples(X_scaled)[0]  # negative values = more anomalous
            # Convert to [0, 1]: Isolation Forest scores typically in [-0.5, 0.5]
            iso_score = float(np.clip((0.5 - iso_raw), 0.0, 1.0))
        except Exception as exc:
            logger.warning("Isolation Forest scoring failed: %s", exc)
            iso_score = 0.5
    else:
        iso_score = 0.5  # neutral fallback when model not loaded

    weighted_z = compute_weighted_z_score(features)

    # Composite: 40% Isolation Forest + 60% weighted z-score
    composite = 0.40 * iso_score + 0.60 * weighted_z

    # Bootstrap entities capped at 0.4 confidence → dampen score
    if profile.get("bootstrap", False):
        composite *= 0.6

    risk_score = float(np.clip(composite * 100.0, 0.0, 100.0))

    return {
        "risk_score": round(risk_score, 2),
        "risk_level": risk_level(risk_score),
        "feature_deviations": {k: round(v, 4) for k, v in features.items()},
        "iso_score": round(iso_score, 4),
        "weighted_z": round(weighted_z, 4),
    }

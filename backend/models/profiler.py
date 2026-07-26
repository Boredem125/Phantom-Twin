"""
profiler.py — Per-entity behavioral profiler for PHANTOM TWIN.

Reads train.csv, builds a statistical profile per entity_id, and serializes
each profile to backend/data/profiles/<entity_id>.json.

Cold-start: new entities with no profile get a bootstrap composite from
the 5 nearest peer entities by entity_type.

Usage:
    python backend/models/profiler.py --input backend/data/train.csv
"""

import argparse
import json
import logging
import os
import math
from collections import Counter, defaultdict
from typing import Any

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("profiler")

PROFILES_DIR = "backend/data/profiles"


# ── Profile builder ────────────────────────────────────────────────────────────

def build_profile(df_entity: pd.DataFrame, entity_id: str) -> dict[str, Any]:
    """Build a behavioral profile dict from a single entity's events."""
    hours = pd.to_datetime(df_entity["timestamp"]).dt.hour.astype(float).tolist()
    hour_mean = float(np.mean(hours)) if hours else 9.0
    hour_std = float(np.std(hours)) if len(hours) > 1 else 1.5

    geo_counts = Counter(df_entity["geo_location"].tolist())
    total_geo = sum(geo_counts.values()) or 1
    geo_weights = {g: c / total_geo for g, c in geo_counts.items()}
    home_geos = list(geo_counts.keys())

    resource_counts = Counter(df_entity["resource_accessed"].tolist())
    total_res = sum(resource_counts.values()) or 1
    resource_freq = {r: c / total_res for r, c in resource_counts.most_common(50)}
    normal_resources = [r for r, freq in resource_freq.items() if freq >= 0.015 or resource_counts[r] >= 2]

    durations = df_entity["session_duration"].dropna().astype(float).tolist()
    avg_duration = float(np.mean(durations)) if durations else 15.0
    dur_std = float(np.std(durations)) if len(durations) > 1 else 5.0

    auth_counts = Counter(df_entity["auth_method"].dropna().tolist())
    preferred_auth = auth_counts.most_common(1)[0][0] if auth_counts else "password"

    fingerprints: list[str] = list(set(df_entity["device_fingerprint"].dropna().tolist()))

    known_ips: list[str] = list(set(df_entity["source_ip"].dropna().tolist()))

    # Simple Markov transition matrix from consecutive events
    resources_seq = df_entity.sort_values("timestamp")["resource_accessed"].tolist()
    markov: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for i in range(len(resources_seq) - 1):
        markov[resources_seq[i]][resources_seq[i + 1]] += 1.0
    # Normalize
    normalized_markov: dict[str, dict[str, float]] = {}
    for src, transitions in markov.items():
        total = sum(transitions.values())
        normalized_markov[src] = {dst: cnt / total for dst, cnt in transitions.items()}

    entity_type = df_entity["entity_type"].iloc[0] if len(df_entity) > 0 else "user"

    return {
        "entity_id": entity_id,
        "entity_type": entity_type,
        "peak_hour": hour_mean,
        "hour_sigma": max(hour_std, 0.5),
        "geo_weights": geo_weights,
        "home_geos": home_geos,
        "resource_freq": resource_freq,
        "normal_resources": normal_resources,
        "markov": normalized_markov,
        "avg_duration": avg_duration,
        "dur_sigma": max(dur_std, 1.0),
        "preferred_auth": preferred_auth,
        "known_fingerprints": fingerprints,
        "known_ips": known_ips,
        "n_events": int(len(df_entity)),
        "bootstrap": False,
    }


def build_bootstrap_profile(
    entity_id: str,
    entity_type: str,
    peer_profiles: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a composite profile from up to 5 nearest peers by entity_type."""
    if not peer_profiles:
        return {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "peak_hour": 9.0,
            "hour_sigma": 2.0,
            "geo_weights": {"Unknown": 1.0},
            "home_geos": ["Unknown"],
            "resource_freq": {},
            "normal_resources": [],
            "markov": {},
            "avg_duration": 15.0,
            "dur_sigma": 5.0,
            "preferred_auth": "password",
            "known_fingerprints": [],
            "known_ips": [],
            "n_events": 0,
            "bootstrap": True,
        }

    n = len(peer_profiles)
    avg_peak_hour = float(np.mean([p["peak_hour"] for p in peer_profiles]))
    avg_hour_sigma = float(np.mean([p["hour_sigma"] for p in peer_profiles]))
    avg_duration = float(np.mean([p["avg_duration"] for p in peer_profiles]))
    avg_dur_sigma = float(np.mean([p["dur_sigma"] for p in peer_profiles]))

    # Merge geo weights
    geo_weights: dict[str, float] = defaultdict(float)
    for p in peer_profiles:
        for g, w in p.get("geo_weights", {}).items():
            geo_weights[g] += w / n
    geo_weights = dict(geo_weights)

    # Merge resource freq
    resource_freq: dict[str, float] = defaultdict(float)
    for p in peer_profiles:
        for r, f in p.get("resource_freq", {}).items():
            resource_freq[r] += f / n
    resource_freq = dict(sorted(resource_freq.items(), key=lambda x: -x[1])[:30])

    auth_counter: Counter = Counter()
    for p in peer_profiles:
        auth_counter[p.get("preferred_auth", "password")] += 1
    preferred_auth = auth_counter.most_common(1)[0][0]

    return {
        "entity_id": entity_id,
        "entity_type": entity_type,
        "peak_hour": avg_peak_hour,
        "hour_sigma": avg_hour_sigma,
        "geo_weights": geo_weights,
        "home_geos": list(geo_weights.keys()),
        "resource_freq": resource_freq,
        "normal_resources": list(resource_freq.keys()),
        "markov": {},
        "avg_duration": avg_duration,
        "dur_sigma": avg_dur_sigma,
        "preferred_auth": preferred_auth,
        "known_fingerprints": [],
        "known_ips": [],
        "n_events": 0,
        "bootstrap": True,
    }


def get_bootstrap_profile(
    entity_id: str,
    entity_type: str,
    all_profiles: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Return a bootstrap composite profile for a new entity."""
    peers = [
        p for p in all_profiles.values()
        if p["entity_type"] == entity_type and not p.get("bootstrap", False)
    ][:5]
    return build_bootstrap_profile(entity_id, entity_type, peers)


# ── Main ───────────────────────────────────────────────────────────────────────

def build_all_profiles(input_path: str, profiles_dir: str = PROFILES_DIR) -> dict[str, Any]:
    """Build and save all entity profiles from training data."""
    logger.info("Loading training data from %s…", input_path)
    df = pd.read_csv(input_path, parse_dates=["timestamp"])
    # Prevent profile poisoning: only profile normal events
    if "label" in df.columns:
        df = df[df["label"] == "normal"].copy()
    df["session_duration"] = pd.to_numeric(df["session_duration"], errors="coerce")
    logger.info("Loaded %d normal rows, %d unique entities.", len(df), df["entity_id"].nunique())

    os.makedirs(profiles_dir, exist_ok=True)
    all_profiles: dict[str, dict[str, Any]] = {}

    entity_ids = df["entity_id"].unique()
    for eid in entity_ids:
        df_e = df[df["entity_id"] == eid].copy()
        profile = build_profile(df_e, eid)
        all_profiles[eid] = profile
        out_path = os.path.join(profiles_dir, f"{eid}.json")
        with open(out_path, "w") as jf:
            json.dump(profile, jf, indent=2)

    logger.info("Saved %d profiles to %s.", len(all_profiles), profiles_dir)
    return all_profiles


def load_profile(entity_id: str, entity_type: str = "user", profiles_dir: str = PROFILES_DIR) -> dict[str, Any]:
    """Load a profile from disk, or return a bootstrap profile if not found."""
    path = os.path.join(profiles_dir, f"{entity_id}.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)

    logger.warning("No profile for %s — loading bootstrap from peers.", entity_id)
    all_profiles: dict[str, dict[str, Any]] = {}
    if os.path.exists(profiles_dir):
        for fname in os.listdir(profiles_dir):
            if fname.endswith(".json"):
                try:
                    with open(os.path.join(profiles_dir, fname)) as pf:
                        p = json.load(pf)
                        all_profiles[p["entity_id"]] = p
                except Exception as exc:  # noqa: BLE001
                    logger.error("Failed to load profile %s: %s", fname, exc)

    return get_bootstrap_profile(entity_id, entity_type, all_profiles)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PHANTOM TWIN — Behavioral profiler")
    parser.add_argument("--input", type=str, default="backend/data/train.csv")
    parser.add_argument("--profiles_dir", type=str, default=PROFILES_DIR)
    args = parser.parse_args()
    build_all_profiles(args.input, args.profiles_dir)

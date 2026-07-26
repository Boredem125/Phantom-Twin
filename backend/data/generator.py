"""
generator.py — Synthetic behavioral access log generator for PHANTOM TWIN.

Generates per-entity behavioral profiles and injects all 8 attack patterns
into a realistic stream of access events.

Usage:
    python backend/data/generator.py --n_entities 200 --n_events 50000 --seed 42
"""

import argparse
import csv
import json
import logging
import math
import os
import random
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

import numpy as np
from faker import Faker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("generator")

fake = Faker()

# ── Constants ─────────────────────────────────────────────────────────────────

ENTITY_TYPES = ["user", "service_account", "edge_device"]
ENTITY_TYPE_WEIGHTS = [0.50, 0.25, 0.25]

AUTH_METHODS = ["password", "sso", "api_key", "certificate", "mfa"]
ATTACK_LABELS = [
    "brute_force",
    "impossible_travel",
    "credential_stuffing",
    "lateral_movement",
    "device_spoofing",
    "low_and_slow",
    "insider_drift",
]

RESOURCE_POOL: list[str] = [
    f"/api/v{v}/{svc}"
    for v in [1, 2]
    for svc in [
        "users", "devices", "configs", "sensors", "alerts", "reports",
        "logs", "admin", "metrics", "files", "assets", "network",
        "firmware", "db/read", "db/write", "keys", "secrets",
        "auth/tokens", "audit", "backup",
    ]
]

GEO_POOL: list[str] = [
    "Mumbai", "Delhi", "Bangalore", "Chennai", "Hyderabad",
    "London", "Berlin", "Paris", "Amsterdam", "Zurich",
    "New York", "Chicago", "Dallas", "San Francisco", "Seattle",
    "Singapore", "Tokyo", "Sydney", "Dubai", "Toronto",
]

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
}

IP_POOL: list[str] = [
    f"10.{a}.{b}.{c}"
    for a in range(1, 5)
    for b in range(1, 10)
    for c in range(1, 30)
]
EXTERNAL_IPS: list[str] = [
    f"{a}.{b}.{c}.{d}"
    for a, b, c, d in [
        (185, 220, 101, 12), (185, 220, 101, 47), (178, 62, 55, 81),
        (91, 108, 4, 15), (194, 165, 16, 78), (23, 45, 67, 89),
        (46, 101, 25, 135), (104, 18, 7, 92),
    ]
]

COMMANDS_POOL: list[str] = [
    "ls", "cat", "grep", "curl", "wget", "ssh", "scp", "cp", "mv",
    "rm", "chmod", "chown", "sudo", "systemctl", "netstat", "ps",
    "kill", "crontab", "iptables", "nc", "nmap", "find", "awk", "sed",
]

SCHEMA_FIELDS = [
    "entity_id", "entity_type", "timestamp", "source_ip", "geo_location",
    "resource_accessed", "auth_method", "session_duration",
    "command_sequence", "device_fingerprint", "label",
]


# ── Haversine distance ─────────────────────────────────────────────────────────

def haversine_km(geo_a: str, geo_b: str) -> float:
    """Return great-circle distance in km between two named geo locations."""
    if geo_a not in GEO_COORDS or geo_b not in GEO_COORDS:
        return 0.0
    lat1, lon1 = GEO_COORDS[geo_a]
    lat2, lon2 = GEO_COORDS[geo_b]
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


# ── Entity profile factory ─────────────────────────────────────────────────────

def make_entity_profile(entity_id: str, entity_type: str, rng: random.Random, np_rng: np.random.Generator) -> dict[str, Any]:
    """Build a randomised per-entity behavioral profile."""
    peak_hour = float(rng.gauss(9.0 if entity_type == "user" else 12.0, 3.0))
    peak_hour = max(0.0, min(23.0, peak_hour))
    hour_sigma = rng.uniform(1.0, 2.5)

    n_geos = rng.randint(2, 4)
    home_geos = rng.sample(GEO_POOL, n_geos)
    geo_weights_raw = np_rng.dirichlet(np.ones(n_geos) * 3.0).tolist()
    geo_weights = {g: w for g, w in zip(home_geos, geo_weights_raw)}

    n_resources = rng.randint(5, 15)
    normal_resources = rng.sample(RESOURCE_POOL, n_resources)
    resource_freq_raw = np_rng.dirichlet(np.ones(n_resources) * 2.0)
    resource_freq = {r: float(f) for r, f in zip(normal_resources, resource_freq_raw)}

    avg_duration = rng.gauss(25.0, 10.0)
    avg_duration = max(5.0, avg_duration)
    dur_sigma = rng.uniform(3.0, 8.0)

    preferred_auth = rng.choices(AUTH_METHODS, weights=[3, 2, 1, 1, 2])[0]

    n_fps = rng.randint(1, 3)
    fingerprints = [str(uuid.uuid4())[:16] for _ in range(n_fps)]

    n_ips = rng.randint(1, 4)
    known_ips = rng.sample(IP_POOL, n_ips)

    # Markov transition matrix for resources
    n_res = len(normal_resources)
    raw_matrix = np_rng.dirichlet(np.ones(n_res) * 2.0, size=n_res)
    markov = {
        r: {s: float(p) for s, p in zip(normal_resources, row)}
        for r, row in zip(normal_resources, raw_matrix)
    }

    return {
        "entity_id": entity_id,
        "entity_type": entity_type,
        "peak_hour": peak_hour,
        "hour_sigma": hour_sigma,
        "geo_weights": geo_weights,
        "home_geos": home_geos,
        "resource_freq": resource_freq,
        "normal_resources": normal_resources,
        "markov": markov,
        "avg_duration": avg_duration,
        "dur_sigma": dur_sigma,
        "preferred_auth": preferred_auth,
        "known_fingerprints": fingerprints,
        "known_ips": known_ips,
        "bootstrap": False,
    }


# ── Normal event generator ─────────────────────────────────────────────────────

def sample_normal_event(
    entity_id: str,
    profile: dict[str, Any],
    ts: datetime,
    last_resource: str | None,
    rng: random.Random,
    np_rng: np.random.Generator,
) -> dict[str, Any]:
    """Sample a single normal event from an entity's profile."""
    hour_raw = rng.gauss(profile["peak_hour"], profile["hour_sigma"])
    hour_raw = max(0.0, min(23.9, hour_raw))
    ts_event = ts.replace(hour=int(hour_raw), minute=rng.randint(0, 59), second=rng.randint(0, 59), microsecond=0)

    geos = list(profile["geo_weights"].keys())
    geo_w = [profile["geo_weights"][g] for g in geos]
    # Occasional travel jitter: 5% chance of secondary geo
    if rng.random() < 0.05 and len(geos) > 1:
        geo = rng.choices(geos, weights=[1 - w for w in geo_w])[0]
    else:
        geo = rng.choices(geos, weights=geo_w)[0]

    # Markov resource transition
    if last_resource and last_resource in profile["markov"]:
        nexts = list(profile["markov"][last_resource].keys())
        weights = [profile["markov"][last_resource][r] for r in nexts]
        resource = rng.choices(nexts, weights=weights)[0]
    else:
        resources = list(profile["resource_freq"].keys())
        weights = [profile["resource_freq"][r] for r in resources]
        resource = rng.choices(resources, weights=weights)[0]

    # Occasionally access adjacent resource
    if rng.random() < 0.08:
        resource = rng.choice(RESOURCE_POOL)

    auth = profile["preferred_auth"] if rng.random() < 0.90 else rng.choice(AUTH_METHODS)
    duration = max(1.0, rng.gauss(profile["avg_duration"], profile["dur_sigma"]))
    fp = rng.choice(profile["known_fingerprints"])

    # 60% chance use known IP, 40% rotate
    if rng.random() < 0.60:
        source_ip = rng.choice(profile["known_ips"])
    else:
        source_ip = rng.choice(IP_POOL)

    n_cmds = rng.randint(1, 5)
    cmds = rng.choices(COMMANDS_POOL, k=n_cmds)

    return {
        "entity_id": entity_id,
        "entity_type": profile["entity_type"],
        "timestamp": ts_event.isoformat(),
        "source_ip": source_ip,
        "geo_location": geo,
        "resource_accessed": resource,
        "auth_method": auth,
        "session_duration": round(duration, 2),
        "command_sequence": ",".join(cmds),
        "device_fingerprint": fp,
        "label": "normal",
    }


# ── Attack injectors ──────────────────────────────────────────────────────────

def inject_brute_force(
    entity_id: str,
    profile: dict[str, Any],
    ts: datetime,
    rng: random.Random,
) -> list[dict[str, Any]]:
    """5–20 failed auth attempts within 60s, same source_ip, then successful."""
    n_attempts = rng.randint(5, 20)
    source_ip = rng.choice(EXTERNAL_IPS)
    geo = rng.choice([g for g in GEO_POOL if g not in profile["home_geos"]])
    events = []
    for i in range(n_attempts):
        event_ts = ts + timedelta(seconds=i * (60 // n_attempts))
        events.append({
            "entity_id": entity_id,
            "entity_type": profile["entity_type"],
            "timestamp": event_ts.isoformat(),
            "source_ip": source_ip,
            "geo_location": geo,
            "resource_accessed": "/api/v1/auth/tokens",
            "auth_method": "password",
            "session_duration": round(rng.uniform(0.5, 2.0), 2),
            "command_sequence": "curl",
            "device_fingerprint": str(uuid.uuid4())[:16],
            "label": "brute_force",
        })
    return events


def inject_impossible_travel(
    entity_id: str,
    profile: dict[str, Any],
    ts: datetime,
    rng: random.Random,
) -> list[dict[str, Any]]:
    """Two logins from geo >2000km apart within 90 minutes."""
    home_geo = rng.choice(profile["home_geos"])
    far_geos = [g for g in GEO_POOL if haversine_km(home_geo, g) > 2000]
    if not far_geos:
        far_geos = [g for g in GEO_POOL if g != home_geo]
    far_geo = rng.choice(far_geos)

    minutes_gap = rng.randint(5, 89)
    ts2 = ts + timedelta(minutes=minutes_gap)

    e1 = {
        "entity_id": entity_id,
        "entity_type": profile["entity_type"],
        "timestamp": ts.isoformat(),
        "source_ip": rng.choice(profile["known_ips"]),
        "geo_location": home_geo,
        "resource_accessed": rng.choice(profile["normal_resources"]),
        "auth_method": profile["preferred_auth"],
        "session_duration": round(rng.gauss(profile["avg_duration"], profile["dur_sigma"]), 2),
        "command_sequence": "ls,cat",
        "device_fingerprint": rng.choice(profile["known_fingerprints"]),
        "label": "normal",
    }
    e2 = {
        "entity_id": entity_id,
        "entity_type": profile["entity_type"],
        "timestamp": ts2.isoformat(),
        "source_ip": rng.choice(EXTERNAL_IPS),
        "geo_location": far_geo,
        "resource_accessed": rng.choice(RESOURCE_POOL),
        "auth_method": profile["preferred_auth"],
        "session_duration": round(rng.gauss(profile["avg_duration"], profile["dur_sigma"]), 2),
        "command_sequence": "curl,grep,awk",
        "device_fingerprint": str(uuid.uuid4())[:16],
        "label": "impossible_travel",
    }
    return [e1, e2]


def inject_credential_stuffing(
    entities: list[str],
    profiles: dict[str, Any],
    ts: datetime,
    rng: random.Random,
) -> list[dict[str, Any]]:
    """10–50 entity_ids, 1–2 source_ips, failure_rate > 0.7."""
    n_entities = rng.randint(10, min(50, len(entities)))
    targets = rng.sample(entities, n_entities)
    n_ips = rng.randint(1, 2)
    source_ips = rng.sample(EXTERNAL_IPS, n_ips)
    failure_rate = rng.uniform(0.70, 0.95)
    events = []
    for i, eid in enumerate(targets):
        entity_type = profiles[eid]["entity_type"]
        is_failure = rng.random() < failure_rate
        event_ts = ts + timedelta(seconds=i * 3)
        events.append({
            "entity_id": eid,
            "entity_type": entity_type,
            "timestamp": event_ts.isoformat(),
            "source_ip": rng.choice(source_ips),
            "geo_location": rng.choice(GEO_POOL),
            "resource_accessed": "/api/v1/auth/tokens",
            "auth_method": "password",
            "session_duration": round(rng.uniform(0.2, 1.5), 2) if is_failure else round(rng.uniform(5.0, 15.0), 2),
            "command_sequence": "curl",
            "device_fingerprint": str(uuid.uuid4())[:16],
            "label": "credential_stuffing",
        })
    return events


def inject_lateral_movement(
    entity_id: str,
    profile: dict[str, Any],
    ts: datetime,
    rng: random.Random,
) -> list[dict[str, Any]]:
    """Access to 5+ resources never in entity's normal set, within single session."""
    novel_resources = [r for r in RESOURCE_POOL if r not in profile["normal_resources"]]
    n_novel = rng.randint(5, min(10, len(novel_resources)))
    targets = rng.sample(novel_resources, n_novel)
    events = []
    for i, resource in enumerate(targets):
        event_ts = ts + timedelta(seconds=i * rng.randint(30, 120))
        events.append({
            "entity_id": entity_id,
            "entity_type": profile["entity_type"],
            "timestamp": event_ts.isoformat(),
            "source_ip": rng.choice(profile["known_ips"]),
            "geo_location": rng.choice(profile["home_geos"]),
            "resource_accessed": resource,
            "auth_method": profile["preferred_auth"],
            "session_duration": round(rng.uniform(2.0, 10.0), 2),
            "command_sequence": ",".join(rng.choices(COMMANDS_POOL, k=3)),
            "device_fingerprint": rng.choice(profile["known_fingerprints"]),
            "label": "lateral_movement",
        })
    return events


def inject_device_spoofing(
    entity_id: str,
    profile: dict[str, Any],
    ts: datetime,
    rng: random.Random,
) -> list[dict[str, Any]]:
    """Login with device_fingerprint not in entity's known set."""
    unknown_fp = str(uuid.uuid4())[:16]
    while unknown_fp in profile["known_fingerprints"]:
        unknown_fp = str(uuid.uuid4())[:16]
    return [{
        "entity_id": entity_id,
        "entity_type": profile["entity_type"],
        "timestamp": ts.isoformat(),
        "source_ip": rng.choice(EXTERNAL_IPS),
        "geo_location": rng.choice(profile["home_geos"]),
        "resource_accessed": rng.choice(profile["normal_resources"]),
        "auth_method": profile["preferred_auth"],
        "session_duration": round(rng.gauss(profile["avg_duration"], profile["dur_sigma"]), 2),
        "command_sequence": ",".join(rng.choices(COMMANDS_POOL, k=3)),
        "device_fingerprint": unknown_fp,
        "label": "device_spoofing",
    }]


def inject_low_and_slow(
    entity_id: str,
    profile: dict[str, Any],
    base_ts: datetime,
    rng: random.Random,
    n_days: int | None = None,
) -> list[dict[str, Any]]:
    """1–3 small off-hours accesses/day building over 3–7 days."""
    if n_days is None:
        n_days = rng.randint(3, 7)
    events = []
    sensitive = [r for r in RESOURCE_POOL if any(k in r for k in ["secrets", "keys", "db", "backup", "admin"])]
    if not sensitive:
        sensitive = RESOURCE_POOL
    for day in range(n_days):
        n_events = rng.randint(1, 3)
        for _ in range(n_events):
            # Off-hours: midnight to 5am or 11pm onwards
            off_hour = rng.choice(list(range(0, 5)) + list(range(23, 24)))
            event_ts = base_ts + timedelta(days=day, hours=off_hour, minutes=rng.randint(0, 59))
            events.append({
                "entity_id": entity_id,
                "entity_type": profile["entity_type"],
                "timestamp": event_ts.isoformat(),
                "source_ip": rng.choice(profile["known_ips"]),
                "geo_location": rng.choice(profile["home_geos"]),
                "resource_accessed": rng.choice(sensitive),
                "auth_method": profile["preferred_auth"],
                "session_duration": round(rng.uniform(1.0, 5.0), 2),
                "command_sequence": ",".join(rng.choices(["cat", "grep", "awk", "curl"], k=2)),
                "device_fingerprint": rng.choice(profile["known_fingerprints"]),
                "label": "low_and_slow",
            })
    return events


def inject_insider_drift(
    entity_id: str,
    profile: dict[str, Any],
    base_ts: datetime,
    rng: random.Random,
    n_days: int | None = None,
) -> list[dict[str, Any]]:
    """Gradual resource footprint expansion over 7–14 days, business hours, no auth failures."""
    if n_days is None:
        n_days = rng.randint(7, 14)
    events = []
    # Expand resource set day by day
    extra_resources = [r for r in RESOURCE_POOL if r not in profile["normal_resources"]]
    for day in range(n_days):
        # Business hours
        hour = rng.randint(9, 17)
        event_ts = base_ts + timedelta(days=day, hours=hour, minutes=rng.randint(0, 59))
        # Access progressively more novel resources
        if day < 4 or not extra_resources:
            resource = rng.choice(profile["normal_resources"])
        else:
            novel_pool = extra_resources[:day]
            resource = rng.choice(novel_pool)
        events.append({
            "entity_id": entity_id,
            "entity_type": profile["entity_type"],
            "timestamp": event_ts.isoformat(),
            "source_ip": rng.choice(profile["known_ips"]),
            "geo_location": rng.choice(profile["home_geos"]),
            "resource_accessed": resource,
            "auth_method": profile["preferred_auth"],
            "session_duration": round(rng.gauss(profile["avg_duration"], profile["dur_sigma"]), 2),
            "command_sequence": ",".join(rng.choices(COMMANDS_POOL, k=2)),
            "device_fingerprint": rng.choice(profile["known_fingerprints"]),
            "label": "insider_drift",
        })
    return events


# ── Main generator ─────────────────────────────────────────────────────────────

def generate(
    n_entities: int = 200,
    n_events: int = 50000,
    seed: int = 42,
    output_dir: str = "backend/data",
) -> None:
    """Generate the full dataset and write train/test/labels CSVs."""
    rng = random.Random(seed)
    np_rng = np.random.default_rng(seed)

    logger.info("Building entity profiles (%d entities)…", n_entities)

    entity_ids: list[str] = [f"ENT-{i:04d}" for i in range(n_entities)]
    entity_types: list[str] = rng.choices(ENTITY_TYPES, weights=ENTITY_TYPE_WEIGHTS, k=n_entities)
    profiles: dict[str, Any] = {}
    for eid, etype in zip(entity_ids, entity_types):
        profiles[eid] = make_entity_profile(eid, etype, rng, np_rng)

    # ── Generate normal events ─────────────────────────────────────────────────
    logger.info("Generating %d normal events…", n_events)
    start_ts = datetime(2025, 1, 1, 0, 0, 0)

    normal_events: list[dict[str, Any]] = []
    last_resource: dict[str, str | None] = {eid: None for eid in entity_ids}

    for i in range(n_events):
        eid = rng.choice(entity_ids)
        ts = start_ts + timedelta(minutes=i * (90 * 24 * 60 / n_events))  # spread over 90 days
        event = sample_normal_event(eid, profiles[eid], ts, last_resource[eid], rng, np_rng)
        last_resource[eid] = event["resource_accessed"]
        normal_events.append(event)

    # ── Inject attacks at 0.5–3% rate ─────────────────────────────────────────
    attack_budget_pct = rng.uniform(0.005, 0.03)
    n_attack_events = int(n_events * attack_budget_pct)
    logger.info("Injecting attack events (target ~%d, %.1f%%)…", n_attack_events, attack_budget_pct * 100)

    attack_events: list[dict[str, Any]] = []

    # Space attack timestamps across the training window
    attack_base_ts = start_ts + timedelta(days=7)
    attack_slots = [attack_base_ts + timedelta(hours=i * 2) for i in range(200)]

    slot_idx = 0
    attacks_per_type: dict[str, int] = defaultdict(int)

    while len(attack_events) < n_attack_events and slot_idx < len(attack_slots):
        attack_type = rng.choice(ATTACK_LABELS)
        ts = attack_slots[slot_idx]
        slot_idx += 1

        if attack_type == "brute_force":
            eid = rng.choice(entity_ids)
            attack_events.extend(inject_brute_force(eid, profiles[eid], ts, rng))

        elif attack_type == "impossible_travel":
            eid = rng.choice(entity_ids)
            attack_events.extend(inject_impossible_travel(eid, profiles[eid], ts, rng))

        elif attack_type == "credential_stuffing":
            attack_events.extend(inject_credential_stuffing(entity_ids, profiles, ts, rng))

        elif attack_type == "lateral_movement":
            eid = rng.choice(entity_ids)
            attack_events.extend(inject_lateral_movement(eid, profiles[eid], ts, rng))

        elif attack_type == "device_spoofing":
            eid = rng.choice(entity_ids)
            attack_events.extend(inject_device_spoofing(eid, profiles[eid], ts, rng))

        elif attack_type == "low_and_slow":
            eid = rng.choice(entity_ids)
            attack_events.extend(inject_low_and_slow(eid, profiles[eid], ts, rng))

        elif attack_type == "insider_drift":
            eid = rng.choice(entity_ids)
            attack_events.extend(inject_insider_drift(eid, profiles[eid], ts, rng))

        attacks_per_type[attack_type] += 1

    logger.info("Attack breakdown: %s", dict(attacks_per_type))

    # ── Inject attacks specifically into the test window ──────────────────────
    # Test window is last 6% of time (≈ last 5.4 days of 90-day window)
    # Inject one instance of each attack type into this window so evaluator sees them
    test_window_start = start_ts + timedelta(days=85)
    test_attack_events: list[dict[str, Any]] = []

    for attack_type in ATTACK_LABELS:
        ts = test_window_start + timedelta(hours=rng.randint(0, 100))
        eid = rng.choice(entity_ids)
        if attack_type == "brute_force":
            test_attack_events.extend(inject_brute_force(eid, profiles[eid], ts, rng))
        elif attack_type == "impossible_travel":
            test_attack_events.extend(inject_impossible_travel(eid, profiles[eid], ts, rng))
        elif attack_type == "credential_stuffing":
            test_attack_events.extend(inject_credential_stuffing(entity_ids, profiles, ts, rng))
        elif attack_type == "lateral_movement":
            test_attack_events.extend(inject_lateral_movement(eid, profiles[eid], ts, rng))
        elif attack_type == "device_spoofing":
            test_attack_events.extend(inject_device_spoofing(eid, profiles[eid], ts, rng))
        elif attack_type == "low_and_slow":
            test_attack_events.extend(inject_low_and_slow(eid, profiles[eid], ts, rng, n_days=3))
        elif attack_type == "insider_drift":
            test_attack_events.extend(inject_insider_drift(eid, profiles[eid], ts, rng, n_days=4))

    # ── Merge and sort ────────────────────────────────────────────────────────
    all_events = normal_events + attack_events + test_attack_events
    all_events.sort(key=lambda e: e["timestamp"])

    # ── Train/test split (90/10) ────────────────────────────────────────────────
    split_idx = int(len(all_events) * 0.90)
    train_events = all_events[:split_idx]
    test_events = all_events[split_idx:]

    os.makedirs(output_dir, exist_ok=True)

    # train.csv — includes labels (needed by profiler)
    train_path = os.path.join(output_dir, "train.csv")
    with open(train_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SCHEMA_FIELDS)
        writer.writeheader()
        writer.writerows(train_events)
    logger.info("Wrote %s (%d rows)", train_path, len(train_events))

    # test.csv — labels stripped
    test_path = os.path.join(output_dir, "test.csv")
    test_fields_no_label = [f for f in SCHEMA_FIELDS if f != "label"]
    with open(test_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=test_fields_no_label)
        writer.writeheader()
        for e in test_events:
            row = {k: v for k, v in e.items() if k != "label"}
            writer.writerow(row)
    logger.info("Wrote %s (%d rows)", test_path, len(test_events))

    # labels_test.csv — held out
    labels_path = os.path.join(output_dir, "labels_test.csv")
    with open(labels_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["entity_id", "timestamp", "label"])
        writer.writeheader()
        for e in test_events:
            writer.writerow({"entity_id": e["entity_id"], "timestamp": e["timestamp"], "label": e["label"]})

    logger.info("Wrote %s (%d rows)", labels_path, len(test_events))

    # Verify anomaly rate in test set
    test_anomalies = sum(1 for e in test_events if e.get("label", "normal") != "normal")
    test_anomaly_rate = test_anomalies / max(len(test_events), 1)
    logger.info(
        "Test set anomaly rate: %.2f%% (%d/%d). Target: 0.5–3%%.",
        test_anomaly_rate * 100, test_anomalies, len(test_events),
    )

    # Save a couple of sample events for manual testing
    sample_dir = os.path.join(os.path.dirname(output_dir), "data", "sample_events")
    os.makedirs(sample_dir, exist_ok=True)
    for label in ATTACK_LABELS + ["normal"]:
        sample = next((e for e in test_events if e.get("label") == label), None)
        if sample is None:
            sample = next((e for e in all_events if e.get("label") == label), None)
        if sample:
            with open(os.path.join(sample_dir, f"{label}.json"), "w") as jf:
                json.dump(sample, jf, indent=2)

    logger.info("Done. Generated %d total events.", len(all_events))


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PHANTOM TWIN — Synthetic data generator")
    parser.add_argument("--n_entities", type=int, default=200)
    parser.add_argument("--n_events", type=int, default=50000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output_dir", type=str, default="backend/data")
    args = parser.parse_args()

    generate(
        n_entities=args.n_entities,
        n_events=args.n_events,
        seed=args.seed,
        output_dir=args.output_dir,
    )

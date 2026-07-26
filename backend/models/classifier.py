"""
classifier.py — Rule-based attack type classifier for PHANTOM TWIN.

Input:  event dict + feature_deviations dict + recent events context
Output: attack_type (str) + confidence (float 0.0–1.0)

Classification is ordered. Returns multi-label list when multiple patterns co-occur.
"""

from __future__ import annotations

import logging
import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("classifier")

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

MAX_PLAUSIBLE_SPEED_KMH = 900.0  # threshold for impossible travel


# ── Helper functions ───────────────────────────────────────────────────────────

def _parse_ts(ts_str: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
    except Exception:
        try:
            return datetime.fromisoformat(str(ts_str))
        except Exception:
            return None


def _haversine_km(geo_a: str, geo_b: str) -> float:
    if geo_a not in GEO_COORDS or geo_b not in GEO_COORDS:
        return 0.0
    lat1, lon1 = GEO_COORDS[geo_a]
    lat2, lon2 = GEO_COORDS[geo_b]
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2
         + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2)
    return 2 * R * math.asin(math.sqrt(max(a, 0.0)))


def _confidence_from_count(n: int, base: float = 5.0, max_val: float = 0.99) -> float:
    return min(max_val, 0.5 + (n - base) / (base * 4))


def _confidence_from_speed(speed_kmh: float) -> float:
    if speed_kmh > 10000:
        return 0.99
    if speed_kmh > 5000:
        return 0.97
    if speed_kmh > 2000:
        return 0.92
    if speed_kmh > 900:
        return 0.85
    return 0.70


def _confidence_from_novelty(novelty: float, breadth_ratio: float) -> float:
    return min(0.97, novelty * 0.5 + min(breadth_ratio / 10.0, 0.5) * 0.5)


# ── Rule checks ────────────────────────────────────────────────────────────────

def _brute_force_check(
    recent_events: list[dict[str, Any]],
    window_seconds: int = 60,
) -> tuple[bool, int]:
    if not recent_events:
        return False, 0

    cutoff = timedelta(seconds=window_seconds)
    event_ts_list = [(e, _parse_ts(str(e.get("timestamp", "")))) for e in recent_events]
    event_ts_list = [(e, ts) for e, ts in event_ts_list if ts is not None]
    if not event_ts_list:
        return False, 0

    latest_ts = max(ts for _, ts in event_ts_list)

    # Group by source_ip, count failures in window
    ip_failures: Counter = Counter()
    for e, ts in event_ts_list:
        if latest_ts - ts <= cutoff:
            duration = float(e.get("session_duration", 99))
            resource = str(e.get("resource_accessed", ""))
            if duration < 3.0 or "auth" in resource or "token" in resource:
                ip_failures[str(e.get("source_ip", ""))] += 1

    if not ip_failures:
        return False, 0

    max_failures = ip_failures.most_common(1)[0][1]
    return max_failures >= 5, max_failures


def _impossible_travel_check(
    event: dict[str, Any],
    recent_events: list[dict[str, Any]],
) -> tuple[bool, float, str, str, float, int]:
    current_geo = str(event.get("geo_location", "Unknown"))
    current_ts = _parse_ts(str(event.get("timestamp", "")))
    if current_ts is None:
        return False, 0.0, "", "", 0.0, 0

    for prev in reversed(recent_events):
        prev_geo = str(prev.get("geo_location", "Unknown"))
        if prev_geo == current_geo or prev_geo == "Unknown":
            continue
        prev_ts = _parse_ts(str(prev.get("timestamp", "")))
        if prev_ts is None:
            continue

        time_delta = abs((current_ts - prev_ts).total_seconds())
        if time_delta < 60:
            continue
        if time_delta > 90 * 60:
            break

        dist_km = _haversine_km(prev_geo, current_geo)
        if dist_km < 500:
            continue

        speed = dist_km / (time_delta / 3600.0)
        if speed > MAX_PLAUSIBLE_SPEED_KMH:
            minutes_gap = int(time_delta / 60)
            return True, round(speed, 1), prev_geo, current_geo, round(dist_km, 1), minutes_gap

    return False, 0.0, "", "", 0.0, 0


def _credential_stuffing_check(
    event: dict[str, Any],
    recent_all_events: list[dict[str, Any]],
    window_seconds: int = 300,
) -> tuple[bool, int, int, float]:
    """
    Looks for a single source IP targeting multiple different entities
    with a high failure rate in a short window.
    """
    if not recent_all_events:
        return False, 0, 0, 0.0

    current_ts = _parse_ts(str(event.get("timestamp", "")))
    if current_ts is None:
        return False, 0, 0, 0.0

    # Group by source IP
    ip_entities = defaultdict(set)
    ip_failures = defaultdict(int)
    ip_total = defaultdict(int)

    for e in recent_all_events:
        ts = _parse_ts(str(e.get("timestamp", "")))
        if ts is None:
            continue
        if abs((current_ts - ts).total_seconds()) <= window_seconds:
            ip = str(e.get("source_ip", ""))
            eid = str(e.get("entity_id", ""))
            ip_entities[ip].add(eid)
            ip_total[ip] += 1
            
            duration = float(e.get("session_duration", 99))
            resource = str(e.get("resource_accessed", ""))
            if duration < 3.0 or "auth" in resource or "token" in resource:
                ip_failures[ip] += 1

    # Check if any IP targeted >= 10 entities
    for ip, entities in ip_entities.items():
        if len(entities) >= 10:
            fail_rate = ip_failures[ip] / max(ip_total[ip], 1)
            if fail_rate > 0.7:
                return True, len(entities), 1, round(fail_rate, 3)

    return False, 0, 0, 0.0


def _device_spoofing_check(
    event: dict[str, Any],
    profile: dict[str, Any],
) -> tuple[bool, str, list[str]]:
    observed_fp = str(event.get("device_fingerprint", ""))
    known_fps: list[str] = profile.get("known_fingerprints", [])
    return observed_fp not in known_fps, observed_fp, known_fps


def _lateral_movement_check(
    deviations: dict[str, float],
    profile: dict[str, Any],
    recent_events: list[dict[str, Any]],
) -> tuple[bool, float, int, int]:
    novelty = float(deviations.get("resource_novelty", 0.0))
    normal_resources = profile.get("normal_resources", [])
    baseline_count = len(normal_resources)

    if novelty < 0.8:
        return False, novelty, 0, baseline_count

    # Count novel resources accessed
    known = set(normal_resources)
    novel_accessed = set(
        str(e.get("resource_accessed", ""))
        for e in recent_events
        if str(e.get("resource_accessed", "")) not in known
    )
    n_novel = len(novel_accessed)

    return (
        n_novel >= 4,
        novelty,
        n_novel,
        baseline_count,
    )


def _low_and_slow_check(
    recent_events: list[dict[str, Any]],
    n_days_min: int = 3,
) -> tuple[bool, int, int]:
    off_hours_events = []
    for e in recent_events:
        ts = _parse_ts(str(e.get("timestamp", "")))
        if ts is None:
            continue
        hour = ts.hour
        if hour < 5 or hour >= 23:
            off_hours_events.append(ts)

    if len(off_hours_events) < 3:
        return False, 0, 0

    date_span = (max(off_hours_events) - min(off_hours_events)).days + 1
    return date_span >= n_days_min, date_span, len(off_hours_events)


def _insider_drift_check(
    entity_id: str,
    profile: dict[str, Any],
    recent_events: list[dict[str, Any]],
    n_days_min: int = 7,
) -> tuple[bool, int, int]:
    if not recent_events:
        return False, 0, 0

    timestamps = []
    novel_resources: set[str] = set()
    known = set(profile.get("normal_resources", []))

    for e in recent_events:
        ts = _parse_ts(str(e.get("timestamp", "")))
        if ts is None:
            continue
        hour = ts.hour
        if 8 <= hour <= 18:
            resource = str(e.get("resource_accessed", ""))
            if resource not in known:
                novel_resources.add(resource)
        timestamps.append(ts)

    if not timestamps:
        return False, 0, 0

    date_span = (max(timestamps) - min(timestamps)).days + 1
    return (
        date_span >= n_days_min and len(novel_resources) >= 2,
        date_span,
        len(novel_resources),
    )


# ── Primary classifier ─────────────────────────────────────────────────────────

def classify(
    event: dict[str, Any],
    deviations: dict[str, float],
    recent_events: list[dict[str, Any]],
    recent_all_events: list[dict[str, Any]],
    profile: dict[str, Any] | None = None,
    risk_score: float = 0.0,
) -> tuple[str, float, dict[str, Any]]:
    if profile is None:
        profile = {}

    meta: dict[str, Any] = {}
    labels: list[tuple[str, float, dict]] = []

    # ── Rule 1: Brute Force ────────────────────────────────────────────────────
    is_bf, n_failures = _brute_force_check(recent_events)
    if is_bf:
        source_ip = str(event.get("source_ip", ""))
        confidence = min(0.99, 0.60 + (n_failures - 5) * 0.02)
        labels.append(("brute_force", confidence, {
            "n_failures": n_failures,
            "window_seconds": 60,
            "source_ip": source_ip,
        }))

    # ── Rule 2: Impossible Travel ──────────────────────────────────────────────
    is_it, speed, geo_a, geo_b, dist_km, minutes_gap = _impossible_travel_check(event, recent_events)
    if is_it:
        confidence = _confidence_from_speed(speed)
        labels.append(("impossible_travel", confidence, {
            "geo_a": geo_a,
            "geo_b": geo_b,
            "distance_km": dist_km,
            "time_gap_minutes": minutes_gap,
            "implied_speed_kmh": speed,
        }))

    # ── Rule 3: Credential Stuffing ────────────────────────────────────────────
    is_cs, n_ents, n_ips, failure_rate = _credential_stuffing_check(event, recent_all_events)
    if is_cs:
        labels.append(("credential_stuffing", 0.85, {
            "n_entities": n_ents,
            "n_source_ips": n_ips,
            "failure_rate": failure_rate,
        }))

    # ── Rule 4: Device Spoofing ────────────────────────────────────────────────
    is_ds, observed_fp, known_fps = _device_spoofing_check(event, profile)
    if is_ds and float(deviations.get("fingerprint_mismatch", 0)) >= 1.0:
        labels.append(("device_spoofing", 0.90, {
            "observed_fp": observed_fp,
            "known_fps": known_fps,
        }))

    # ── Rule 5: Lateral Movement ───────────────────────────────────────────────
    is_lm, novelty, n_novel, baseline_count = _lateral_movement_check(deviations, profile, recent_events)
    if is_lm:
        labels.append(("lateral_movement", 0.95, {
            "resource_novelty": novelty,
            "n_novel_resources": n_novel,
            "baseline_resource_count": baseline_count,
        }))

    # ── Rule 6: Low and Slow ───────────────────────────────────────────────────
    is_las, n_days, n_off_events = _low_and_slow_check(recent_events)
    if is_las:
        labels.append(("low_and_slow", 0.75, {
            "n_days": n_days,
            "n_off_hours_events": n_off_events,
        }))

    # ── Rule 7: Insider Drift ──────────────────────────────────────────────────
    is_id, drift_days, n_novel_res = _insider_drift_check(
        str(event.get("entity_id", "")), profile, recent_events
    )
    if is_id:
        labels.append(("insider_drift", min(0.7, 0.4 + drift_days * 0.02), {
            "n_days": drift_days,
            "n_novel_resources": n_novel_res,
        }))

    # ── Select result ──────────────────────────────────────────────────────────
    # Attack pattern priority (more specific complex behaviors take precedence)
    ATTACK_PRIORITY = {
        "credential_stuffing": 10,
        "brute_force": 9,
        "lateral_movement": 8,
        "low_and_slow": 7,
        "insider_drift": 6,
        "impossible_travel": 5,
        "device_spoofing": 4,
        "normal": 0
    }

    if not labels:
        normal_confidence = round(max(0.01, 1.0 - (risk_score / 100.0)), 4)
        return "normal", normal_confidence, {}

    if len(labels) == 1:
        attack_type, confidence, detail_meta = labels[0]
        meta.update(detail_meta)
        return attack_type, round(confidence, 4), meta

    # Multi-label: sort by priority desc, then confidence desc
    labels.sort(key=lambda x: (-ATTACK_PRIORITY.get(x[0], 0), -x[1]))
    primary_type, primary_conf, primary_meta = labels[0]
    meta.update(primary_meta)
    meta["co_labels"] = [
        {"attack_type": t, "confidence": round(c, 4)} for t, c, _ in labels[1:]
    ]
    return primary_type, round(primary_conf, 4), meta

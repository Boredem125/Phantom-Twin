"""
explainer.py — Natural language explanation generator for PHANTOM TWIN.

Turns classified alert data into human-readable English and a structured
feature attribution dict.

Usage:
    from backend.models.explainer import explain
    result = explain(event, deviations, profile, attack_type, confidence, meta)
"""

import logging
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("explainer")

# ── Feature weight constants (mirrors detector.py) ─────────────────────────────

FEATURE_WEIGHTS: dict[str, float] = {
    "hour_deviation": 0.20,
    "geo_deviation": 0.25,
    "resource_novelty": 0.20,
    "session_duration_z": 0.10,
    "auth_method_change": 0.15,
    "fingerprint_mismatch": 0.10,
}

FEATURE_LABELS: dict[str, str] = {
    "hour_deviation": "unusual login hour",
    "geo_deviation": "unexpected geographic location",
    "resource_novelty": "access to novel/unknown resource",
    "session_duration_z": "abnormal session duration",
    "auth_method_change": "change in authentication method",
    "fingerprint_mismatch": "unrecognized device fingerprint",
}


# ── Attack-specific detail builders ───────────────────────────────────────────

def _detail_impossible_travel(meta: dict[str, Any]) -> str:
    geo_a = meta.get("geo_a", "Unknown")
    geo_b = meta.get("geo_b", "Unknown")
    dist = meta.get("distance_km", 0)
    minutes = meta.get("time_gap_minutes", 0)
    speed = meta.get("implied_speed_kmh", 0)
    return (
        f"Origin: {geo_a} → {geo_b}, {dist:,.0f} km in {minutes} min "
        f"({speed:,.0f} km/h implied — physically impossible)."
    )


def _detail_brute_force(meta: dict[str, Any]) -> str:
    n = meta.get("n_failures", 5)
    window = meta.get("window_seconds", 60)
    ip = meta.get("source_ip", "unknown")
    return f"{n} failed authentication attempts in {window}s from {ip}."


def _detail_device_spoofing(meta: dict[str, Any]) -> str:
    observed = meta.get("observed_fp", "unknown")
    known = meta.get("known_fps", [])
    known_str = ", ".join(known[:4]) or "none"
    return f"Known fingerprints: [{known_str}]. Observed: {observed}."


def _detail_lateral_movement(meta: dict[str, Any]) -> str:
    n_novel = meta.get("n_novel_resources", 0)
    baseline = meta.get("baseline_resource_count", 0)
    breadth = meta.get("breadth_ratio", 0)
    return (
        f"{n_novel} resources accessed outside normal set of {baseline}. "
        f"Access breadth {breadth:.1f}× baseline."
    )


def _detail_credential_stuffing(meta: dict[str, Any]) -> str:
    n_ents = meta.get("n_entities", 0)
    n_ips = meta.get("n_source_ips", 0)
    failure_rate = meta.get("failure_rate", 0)
    return (
        f"{n_ents} entity IDs targeted from {n_ips} source IP(s), "
        f"failure rate {failure_rate:.0%}."
    )


def _detail_low_and_slow(meta: dict[str, Any]) -> str:
    n_days = meta.get("n_days", 0)
    n_events = meta.get("n_off_hours_events", 0)
    return f"Pattern detected over {n_days} days, {n_events} off-hours access events cumulative."


def _detail_insider_drift(meta: dict[str, Any]) -> str:
    n_days = meta.get("n_days", 0)
    n_novel = meta.get("n_novel_resources", 0)
    return (
        f"Gradual resource footprint expansion: {n_novel} novel resources accessed "
        f"over {n_days} days, all within business hours, no authentication failures."
    )


ATTACK_DETAIL_BUILDERS = {
    "impossible_travel": _detail_impossible_travel,
    "brute_force": _detail_brute_force,
    "device_spoofing": _detail_device_spoofing,
    "lateral_movement": _detail_lateral_movement,
    "credential_stuffing": _detail_credential_stuffing,
    "low_and_slow": _detail_low_and_slow,
    "insider_drift": _detail_insider_drift,
}


# ── Feature attribution builder ────────────────────────────────────────────────

def _build_attribution(
    event: dict[str, Any],
    deviations: dict[str, float],
    profile: dict[str, Any],
) -> dict[str, Any]:
    """Build per-feature attribution dict with baseline, observed, delta, weight."""
    attribution: dict[str, Any] = {}

    # Hour
    try:
        import pandas as pd
        ts = pd.to_datetime(event.get("timestamp", ""))
        observed_hour = float(ts.hour + ts.minute / 60.0)
    except Exception:
        observed_hour = 12.0
    attribution["hour_deviation"] = {
        "baseline": round(profile.get("peak_hour", 12.0), 2),
        "observed": round(observed_hour, 2),
        "delta": round(abs(observed_hour - profile.get("peak_hour", 12.0)), 2),
        "weight": FEATURE_WEIGHTS["hour_deviation"],
        "score": round(deviations.get("hour_deviation", 0.0), 4),
    }

    # Geo
    event_geo = str(event.get("geo_location", "Unknown"))
    home_geos = profile.get("home_geos", [])
    primary_geo = home_geos[0] if home_geos else "Unknown"
    attribution["geo_deviation"] = {
        "baseline": primary_geo,
        "observed": event_geo,
        "delta": "known_geo" if event_geo in home_geos else "unknown_geo",
        "weight": FEATURE_WEIGHTS["geo_deviation"],
        "score": round(deviations.get("geo_deviation", 0.0), 4),
    }

    # Resource novelty
    resource = str(event.get("resource_accessed", ""))
    normal_resources = profile.get("normal_resources", [])
    attribution["resource_novelty"] = {
        "baseline": f"top-{len(normal_resources[:20])} known resources",
        "observed": resource,
        "delta": "novel_resource" if resource not in set(normal_resources[:20]) else "known_resource",
        "weight": FEATURE_WEIGHTS["resource_novelty"],
        "score": round(deviations.get("resource_novelty", 0.0), 4),
    }

    # Session duration
    try:
        duration = float(event.get("session_duration", 15.0))
    except (ValueError, TypeError):
        duration = 15.0
    avg_dur = profile.get("avg_duration", 15.0)
    attribution["session_duration_z"] = {
        "baseline": round(avg_dur, 2),
        "observed": round(duration, 2),
        "delta": round(abs(duration - avg_dur), 2),
        "weight": FEATURE_WEIGHTS["session_duration_z"],
        "score": round(deviations.get("session_duration_z", 0.0), 4),
    }

    # Auth method
    event_auth = str(event.get("auth_method", ""))
    preferred_auth = str(profile.get("preferred_auth", ""))
    attribution["auth_method_change"] = {
        "baseline": preferred_auth,
        "observed": event_auth,
        "delta": "method_unchanged" if event_auth == preferred_auth else "method_changed",
        "weight": FEATURE_WEIGHTS["auth_method_change"],
        "score": round(deviations.get("auth_method_change", 0.0), 4),
    }

    # Fingerprint
    event_fp = str(event.get("device_fingerprint", ""))
    known_fps = profile.get("known_fingerprints", [])
    attribution["fingerprint_mismatch"] = {
        "baseline": known_fps,
        "observed": event_fp,
        "delta": "known_device" if event_fp in known_fps else "unknown_device",
        "weight": FEATURE_WEIGHTS["fingerprint_mismatch"],
        "score": round(deviations.get("fingerprint_mismatch", 0.0), 4),
    }

    return attribution


def _top_risk_factors(deviations: dict[str, float], n: int = 3) -> list[str]:
    """Return top-N human-readable risk factor strings."""
    sorted_features = sorted(
        [(k, v) for k, v in deviations.items() if k in FEATURE_LABELS],
        key=lambda x: -x[1],
    )
    return [FEATURE_LABELS[k] for k, v in sorted_features[:n] if v > 0.1]


# ── Main explainer ─────────────────────────────────────────────────────────────

def explain(
    event: dict[str, Any],
    deviations: dict[str, float],
    profile: dict[str, Any],
    attack_type: str,
    confidence: float,
    meta: dict[str, Any] | None = None,
    phantom_activated_at: str | None = None,
) -> dict[str, Any]:
    """
    Generate a human-readable explanation and structured attribution.

    Returns:
        text: str — 2–4 sentence explanation
        attribution: dict — per-feature attribution
        summary: str — short one-liner for alert card
    """
    if meta is None:
        meta = {}

    entity_id = str(event.get("entity_id", "Unknown"))
    entity_type = str(event.get("entity_type", "user"))
    resource = str(event.get("resource_accessed", "unknown resource"))
    timestamp = str(event.get("timestamp", "unknown time"))
    confidence_pct = int(confidence * 100)

    risk_factors = _top_risk_factors(deviations)
    risk_factor_str = "; ".join(risk_factors) if risk_factors else "behavioral deviation"

    attack_detail = ""
    detail_builder = ATTACK_DETAIL_BUILDERS.get(attack_type)
    if detail_builder:
        try:
            attack_detail = detail_builder(meta)
        except Exception as exc:
            logger.warning("Detail builder failed for %s: %s", attack_type, exc)
            attack_detail = ""

    phantom_note = ""
    if phantom_activated_at:
        phantom_note = f" Phantom Twin session activated at {phantom_activated_at}."

    # Main explanation text
    text = (
        f"{entity_id} ({entity_type}) accessed {resource} at {timestamp}. "
        f"Risk factors: {risk_factor_str}. "
        f"Attack pattern: {attack_type.replace('_', ' ').title()} ({confidence_pct}% confidence). "
    )
    if attack_detail:
        text += attack_detail
    if phantom_note:
        text += phantom_note

    # Short summary (for alert card)
    summary = (
        f"{attack_type.replace('_', ' ').title()} — "
        f"{confidence_pct}% confidence on {entity_id}"
    )

    attribution = _build_attribution(event, deviations, profile)

    # Co-labels if multi-label
    co_labels = meta.get("co_labels", [])

    return {
        "text": text,
        "summary": summary,
        "attribution": attribution,
        "attack_type": attack_type,
        "confidence": confidence,
        "co_labels": co_labels,
        "attack_detail": attack_detail,
    }

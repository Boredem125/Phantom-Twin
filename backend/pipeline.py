"""
pipeline.py — End-to-end event processing pipeline for PHANTOM TWIN.

Chains: profiler → detector → classifier → explainer → phantom

Usage:
    python backend/pipeline.py --event backend/data/sample_events/brute_force.json
"""

import argparse
import json
import logging
import os
import sys
from collections import deque
from datetime import datetime, timedelta
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pipeline")

# ── Module path setup ──────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.models.profiler import load_profile
from backend.models.detector import score_event, load_model, risk_level
from backend.models.classifier import classify
from backend.models.explainer import explain
from backend.models.phantom import phantom_manager

# ── Shared state ───────────────────────────────────────────────────────────────

# Rolling window: last 1000 events per entity (for context-aware classification)
_entity_recent_events: dict[str, deque] = {}
# Rolling window: last 1000 events across all entities (for credential stuffing)
_global_recent_events: deque = deque(maxlen=1000)

# Loaded model (lazy)
_model: Any = None
_model_loaded: bool = False


def _get_model() -> Any:
    """Lazy-load the Isolation Forest model."""
    global _model, _model_loaded
    if not _model_loaded:
        model_path = "backend/models/iso_forest.pkl"
        if os.path.exists(model_path):
            try:
                _model = load_model()
                logger.info("Isolation Forest model loaded.")
            except Exception as exc:
                logger.warning("Could not load model: %s. Scoring without IF.", exc)
                _model = None
        else:
            logger.warning("Model not found at %s. Scoring without IF.", model_path)
            _model = None
        _model_loaded = True
    return _model


def _get_recent_events(entity_id: str) -> list[dict[str, Any]]:
    if entity_id not in _entity_recent_events:
        _entity_recent_events[entity_id] = deque(maxlen=500)
    return list(_entity_recent_events[entity_id])


def _push_event(entity_id: str, event: dict[str, Any]) -> None:
    if entity_id not in _entity_recent_events:
        _entity_recent_events[entity_id] = deque(maxlen=500)
    _entity_recent_events[entity_id].append(event)
    _global_recent_events.append(event)


# ── Core pipeline ──────────────────────────────────────────────────────────────

def process_event(event: dict[str, Any]) -> dict[str, Any]:
    """
    Process a single raw event through the full PHANTOM TWIN pipeline.

    Returns an enriched alert dict.
    """
    entity_id = str(event.get("entity_id", "UNKNOWN"))
    entity_type = str(event.get("entity_type", "user"))

    # 1. Load profile (or bootstrap)
    profile = load_profile(entity_id, entity_type)

    # 2. Score event
    model = _get_model()
    score_result = score_event(event, profile, model)

    risk_score: float = score_result["risk_score"]
    level: str = score_result["risk_level"]
    deviations: dict[str, float] = score_result["feature_deviations"]

    # 3. Push to history first to include current event in rolling windows
    _push_event(entity_id, event)

    recent_events = _get_recent_events(entity_id)
    recent_all = list(_global_recent_events)

    attack_type, confidence, class_meta = classify(
        event=event,
        deviations=deviations,
        recent_events=recent_events,
        recent_all_events=recent_all,
        profile=profile,
        risk_score=risk_score,
    )

    # 4. Activate Phantom Twin if HIGH or CRITICAL
    phantom_session_dict: dict[str, Any] | None = None
    phantom_activated_at: str | None = None

    if level in ("HIGH", "CRITICAL"):
        source_ip = str(event.get("source_ip", "unknown"))
        session = phantom_manager.get(entity_id)
        if not session or session.status != "ACTIVE":
            session = phantom_manager.activate(entity_id, profile, source_ip)
            event["_newly_activated"] = True
        phantom_session_dict = session.to_dict()
        phantom_activated_at = session.activated_at.isoformat()
        logger.info("PHANTOM TWIN active for %s (risk=%s)", entity_id, level)

    # 5. Explain
    explanation = explain(
        event=event,
        deviations=deviations,
        profile=profile,
        attack_type=attack_type,
        confidence=confidence,
        meta=class_meta,
        phantom_activated_at=phantom_activated_at,
    )

    alert: dict[str, Any] = {
        "alert_id": _generate_alert_id(),
        "timestamp": str(event.get("timestamp", datetime.utcnow().isoformat())),
        "event": event,
        "entity_id": entity_id,
        "entity_type": entity_type,
        "risk_score": risk_score,
        "risk_level": level,
        "attack_type": attack_type,
        "confidence": confidence,
        "explanation": explanation["text"],
        "explanation_summary": explanation["summary"],
        "feature_attribution": explanation["attribution"],
        "co_labels": explanation.get("co_labels", []),
        "profile_bootstrap": profile.get("bootstrap", False),
        "phantom_session": phantom_session_dict,
        "phantom_activated": phantom_session_dict is not None,
    }

    return alert


def _generate_alert_id() -> str:
    """Generate a short unique alert ID."""
    import uuid
    return f"ALT-{uuid.uuid4().hex[:8].upper()}"


# ── CLI entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PHANTOM TWIN — Event pipeline")
    parser.add_argument("--event", type=str, required=True, help="Path to JSON event file")
    args = parser.parse_args()

    if not os.path.exists(args.event):
        logger.error("Event file not found: %s", args.event)
        sys.exit(1)

    with open(args.event) as f:
        raw_event = json.load(f)

    result = process_event(raw_event)
    print(json.dumps(result, indent=2, default=str))

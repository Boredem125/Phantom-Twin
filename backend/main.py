"""
main.py — FastAPI application with WebSocket live alert streaming for PHANTOM TWIN.

Endpoints:
    POST /api/event                   Process event, return alert
    GET  /api/alerts                  Return last N alerts
    GET  /api/entity/{id}             Entity profile + last 100 events
    GET  /api/phantom/{id}            Active phantom session for entity
    POST /api/phantom/{id}/terminate  Terminate phantom session
    GET  /api/status                  System health / counters
    WS   /ws/alerts                   WebSocket live alert stream

Run:
    uvicorn backend.main:app --reload --port 8000
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys

# Load API Key from environment
api_key = os.environ.get("GROQ_API_KEY", os.environ.get("GROK_API_KEY", ""))
if api_key:
    os.environ["GROQ_API_KEY"] = api_key

from collections import deque
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError

# ── Path setup ─────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.schemas import (
    AlertOut,
    EntityProfileOut,
    EventInput,
    PhantomActionInput,
    PhantomSessionOut,
    PhantomSummaryOut,
    RagQueryInput,
    RagQueryOut,
    SystemStatusOut,
)
from backend.pipeline import process_event
from backend.models.profiler import load_profile
from backend.models.phantom import phantom_manager
from backend.rag import rag_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("main")

# ── App init ───────────────────────────────────────────────────────────────────

app = FastAPI(
    title="PHANTOM TWIN",
    description="Behavioral anomaly detection + active deception for Hackathon.",
    version="1.0.0",
)

@app.on_event("startup")
async def startup_event():
    from backend.tools.synthetic_generator import start_generator
    await start_generator()
    logger.info("Synthetic event generator started.")

@app.on_event("shutdown")
async def shutdown_event():
    from backend.tools.synthetic_generator import stop_generator
    await stop_generator()
    logger.info("Synthetic event generator stopped.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Shared state ───────────────────────────────────────────────────────────────

_alert_store: deque[dict[str, Any]] = deque(maxlen=500)
_event_history: dict[str, deque] = {}  # entity_id → last 100 events
_total_events_processed: int = 0
_entities_seen: set[str] = set()
_ws_clients: set[WebSocket] = set()
_ws_broadcast_counter: int = 0          # throttle counter


# ── WebSocket manager ──────────────────────────────────────────────────────────

async def _broadcast_alert(alert: dict[str, Any]) -> None:
    """Broadcast an alert to all connected WebSocket clients.

    Throttle: always send HIGH/CRITICAL; send LOW/MEDIUM every 3rd event so
    the UI stays responsive under high synthetic load.
    """
    global _ws_broadcast_counter
    if not _ws_clients:
        return

    level = alert.get("risk_level", "LOW")
    if level in ("LOW", "MEDIUM"):
        _ws_broadcast_counter += 1
        if _ws_broadcast_counter % 3 != 0:  # skip 2 out of 3 low-noise events
            return

    dead: list[WebSocket] = []
    payload = json.dumps(alert, default=str)
    for ws in list(_ws_clients):
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.discard(ws)


_rag_batch: list[dict[str, Any]] = []   # batch RAG upserts to avoid per-event overhead
_rag_batch_counter: int = 0

def _record_alert(alert: dict[str, Any]) -> None:
    """Store alert in memory. RAG upserts are batched to avoid blocking the event loop."""
    global _total_events_processed, _rag_batch, _rag_batch_counter

    event = alert.get("event", {})
    entity_id = str(alert.get("entity_id") or event.get("entity_id", "UNKNOWN"))

    _total_events_processed += 1
    _entities_seen.add(entity_id)
    _alert_store.appendleft(alert)

    if entity_id not in _event_history:
        _event_history[entity_id] = deque(maxlen=100)
    _event_history[entity_id].appendleft(event)

    # Batch RAG upserts: only index every 20th alert to avoid blocking
    _rag_batch.append(alert)
    _rag_batch_counter += 1
    if _rag_batch_counter % 20 == 0:
        batch, _rag_batch = _rag_batch[:20], _rag_batch[20:]
        try:
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, rag_engine.upsert_alerts, batch)
        except Exception:
            pass


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.post("/api/event", response_model=AlertOut, status_code=200)
async def ingest_event(body: EventInput) -> Any:
    """Process a single access event through the full pipeline.
    
    process_event() is CPU-bound/sync — run it in a thread pool so the
    asyncio event loop stays free for WebSocket connections.
    """
    event_dict = body.model_dump()

    loop = asyncio.get_event_loop()
    try:
        alert = await loop.run_in_executor(None, process_event, event_dict)
    except Exception as exc:
        logger.exception("Pipeline error processing event: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Pipeline error: {exc}",
        ) from exc

    entity_id = str(alert.get("entity_id", event_dict.get("entity_id", "UNKNOWN")))
    _record_alert(alert)
    asyncio.create_task(_broadcast_alert(alert))

    if event_dict.get("_newly_activated"):
        asyncio.create_task(_simulate_generic_phantom_activity(entity_id))

    return alert


@app.get("/api/alerts", response_model=list[AlertOut])
async def get_alerts(
    n: int = 50,
    risk_level: str | None = None,
    attack_type: str | None = None,
    entity_type: str | None = None,
) -> Any:
    """Return last N alerts, optionally filtered."""
    alerts = list(_alert_store)[:n]

    if risk_level:
        alerts = [a for a in alerts if a.get("risk_level") == risk_level.upper()]
    if attack_type:
        alerts = [a for a in alerts if a.get("attack_type") == attack_type.lower()]
    if entity_type:
        alerts = [a for a in alerts if a.get("entity_type") == entity_type.lower()]

    return alerts


@app.get("/api/entity/{entity_id}", response_model=dict[str, Any])
async def get_entity(entity_id: str) -> Any:
    """Return entity profile and last 100 events."""
    profile = load_profile(entity_id)
    if not profile:
        raise HTTPException(status_code=404, detail=f"Entity {entity_id} not found.")

    events = list(_event_history.get(entity_id, []))

    # Find related alerts
    related_alerts = [
        a for a in _alert_store
        if a.get("entity_id") == entity_id
    ][:30]

    return {
        "profile": profile,
        "recent_events": events,
        "recent_alerts": related_alerts,
    }


@app.get("/api/phantom/{entity_id}", response_model=dict[str, Any])
async def get_phantom_session(entity_id: str) -> Any:
    """Return the active phantom session for an entity."""
    session = phantom_manager.get(entity_id)
    if session is None:
        # Check for summary (terminated session)
        summary = phantom_manager.get_summary(entity_id)
        if summary:
            return {"status": "TERMINATED", "summary": summary.to_dict()}
        raise HTTPException(status_code=404, detail=f"No phantom session for {entity_id}.")
    return {"status": "ACTIVE", "session": session.to_dict()}


@app.post("/api/phantom/{entity_id}/terminate", response_model=PhantomSummaryOut)
async def terminate_phantom(entity_id: str) -> Any:
    """Analyst manually terminates a phantom session."""
    summary = phantom_manager.terminate(entity_id)
    if summary is None:
        raise HTTPException(status_code=404, detail=f"No active phantom session for {entity_id}.")

    logger.info("Analyst terminated phantom session for %s.", entity_id)
    return summary.to_dict()


@app.post("/api/phantom/{entity_id}/action")
async def log_phantom_action(entity_id: str, body: PhantomActionInput) -> Any:
    """Log an attacker action into an active phantom session (used by demo_replay)."""
    session = phantom_manager.get(entity_id)
    if session is None or session.status != "ACTIVE":
        raise HTTPException(status_code=404, detail=f"No active phantom session for {entity_id}.")
    session.log_action(body.action_type, body.details)
    return {"logged": True, "n_actions": session.n_actions if hasattr(session, "n_actions") else len(session.actions)}



async def _run_live_attack_demo() -> None:
    """Run a compact live scenario: attack succeeds from attacker view, but lands in Phantom."""
    event = {
        "entity_id": "ENT-DEMO-INDIA",
        "entity_type": "user",
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": "103.48.199.44",
        "geo_location": "Mumbai",
        "resource_accessed": "/api/v1/auth/tokens",
        "auth_method": "password",
        "session_duration": 1.2,
        "command_sequence": "curl,hydra,ssh",
        "device_fingerprint": "unknown-demo-fp-77",
    }

    loop = asyncio.get_event_loop()
    try:
        alert = await loop.run_in_executor(None, process_event, event)
    except Exception as exc:
        logger.exception("Live attack demo pipeline failed: %s", exc)
        return

    if not alert.get("phantom_session"):
        profile = load_profile(event["entity_id"], event["entity_type"])
        session = phantom_manager.activate(event["entity_id"], profile, event["source_ip"])
        alert["risk_score"] = max(float(alert.get("risk_score", 0)), 96.0)
        alert["risk_level"] = "CRITICAL"
        alert["attack_type"] = "brute_force"
        alert["confidence"] = max(float(alert.get("confidence", 0)), 0.97)
        alert["phantom_session"] = session.to_dict()
        alert["phantom_activated"] = True

    alert["explanation_summary"] = (
        "Demo attacker received fake auth success and is now contained in Phantom Twin."
    )
    alert["explanation"] = (
        "A scripted brute-force login from Mumbai was allowed to appear successful to the "
        "attacker. PHANTOM TWIN silently swapped the session into a synthetic honeypot, "
        "where every follow-on action is logged without touching production resources."
    )

    _record_alert(alert)
    await _broadcast_alert(alert)

    await asyncio.sleep(0.8)
    session = phantom_manager.get(event["entity_id"])
    if not session:
        return
    session.respond_to_auth()

    scripted_steps = [
        ("resource", "/decoy/api/v1/secrets/master-key"),
        ("escalate", "admin"),
        ("lateral", "/decoy/api/v1/network/routing-table"),
        ("read", "/decoy/assets/credentials.json"),
        ("resource", "/decoy/api/v1/firmware/update"),
    ]
    import random
    while True:
        await asyncio.sleep(random.uniform(2.0, 4.5))
        session = phantom_manager.get(event["entity_id"])
        if not session or session.status != "ACTIVE":
            return
        
        step, value = random.choice(scripted_steps)
        if step == "resource":
            session.respond_to_resource_probe(value)
        elif step == "escalate":
            session.respond_to_escalation_attempt()
        elif step == "lateral":
            session.respond_to_lateral_probe(value)
        elif step == "read":
            session.respond_to_data_read(value)

async def _simulate_generic_phantom_activity(entity_id: str) -> None:
    """Randomly generate attacker commands in a freshly activated generic decoy."""
    try:
        await asyncio.sleep(1.5)
        session = phantom_manager.get(entity_id)
        if not session or session.status != "ACTIVE":
            logger.warning(f"Decoy {entity_id} NOT ACTIVE in generic simulate")
            return
        
        session.respond_to_auth()
        
        import random
        steps = [
            ("resource", "/etc/passwd"),
            ("resource", "/var/log/auth.log"),
            ("escalate", "root"),
            ("lateral", "10.0.0.52"),
            ("read", "id_rsa"),
            ("lateral", "10.0.0.100"),
            ("escalate", "admin"),
            ("read", "config.yml"),
            ("resource", "/api/v1/admin/users")
        ]
        
        while True:
            await asyncio.sleep(random.uniform(2.0, 4.5))
            session = phantom_manager.get(entity_id)
            if not session or session.status != "ACTIVE":
                logger.info(f"Decoy {entity_id} terminating infinite loop")
                return
            
            step, value = random.choice(steps)
            if step == "resource":
                session.respond_to_resource_probe(value)
            elif step == "escalate":
                session.respond_to_escalation_attempt()
            elif step == "lateral":
                session.respond_to_lateral_probe(value)
            elif step == "read":
                session.respond_to_data_read(value)
    except Exception as exc:
        logger.exception("Error in generic phantom activity for %s: %s", entity_id, exc)


@app.post("/api/demo/live-attack")
async def start_live_attack_demo() -> Any:
    """Start the live attacker-into-honeypot demo sequence."""
    asyncio.create_task(_run_live_attack_demo())
    return {
        "started": True,
        "scenario": "brute_force_fake_success_to_phantom_honeypot",
        "message": "Live demo started. Watch the alert queue and Phantom pane.",
    }


@app.post("/api/rag/query", response_model=RagQueryOut)
async def query_rag(body: RagQueryInput) -> Any:
    """Answer a natural-language investigation query over live alert state."""
    summaries = [summary.to_dict() for summary in getattr(phantom_manager, "_summaries", {}).values()]
    loop = asyncio.get_event_loop()
    import functools
    fn = functools.partial(
        rag_engine.query,
        question=body.question,
        alerts=list(_alert_store),
        active_phantoms=phantom_manager.all_active(),
        summaries=summaries,
    )
    return await loop.run_in_executor(None, fn)


@app.post("/api/rag/index")
async def index_rag() -> Any:
    """Force indexing of the current alert window into Pinecone/local RAG."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, rag_engine.upsert_alerts, list(_alert_store))

@app.get("/api/status", response_model=SystemStatusOut)
async def get_status() -> Any:
    """Return live system health counters."""
    return {
        "total_events_processed": _total_events_processed,
        "total_alerts": len(_alert_store),
        "active_phantom_sessions": phantom_manager.active_count(),
        "entities_monitored": len(_entities_seen),
        "health": "NOMINAL",
    }


# ── WebSocket ──────────────────────────────────────────────────────────────────

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket) -> None:
    """Stream live alerts to connected dashboard clients."""
    await websocket.accept()
    _ws_clients.add(websocket)
    logger.info("WebSocket client connected. Total clients: %d", len(_ws_clients))

    # Send last 20 alerts on connect (so dashboard isn't empty)
    recent = list(_alert_store)[:20]
    for alert in reversed(recent):
        try:
            await websocket.send_text(json.dumps(alert, default=str))
        except Exception:
            break

    try:
        while True:
            # Keep alive — ping every 30s
            await asyncio.sleep(30)
            try:
                await websocket.send_text(json.dumps({"type": "ping", "ts": datetime.utcnow().isoformat()}))
            except Exception:
                break
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected.")
    finally:
        _ws_clients.discard(websocket)




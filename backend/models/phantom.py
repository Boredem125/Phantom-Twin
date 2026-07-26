"""
phantom.py — Phantom Twin decoy session generator for PHANTOM TWIN.

When a HIGH or CRITICAL alert fires, a PhantomSession is activated:
  - Generates synthetic decoy responses to attacker auth attempts
  - Logs every attacker action inside the decoy
  - Auto-terminates after configurable timeout (default 10 min)
  - Stored in-memory, keyed by entity_id

Usage:
    from backend.models.phantom import phantom_manager
    session = phantom_manager.activate(entity_id, profile, source_ip)
    phantom_manager.log_action(entity_id, "AUTH_ATTEMPT", {"resource": "/api/v1/secrets"})
    summary = phantom_manager.terminate(entity_id)
"""

import logging
import random
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("phantom")

# ── Constants ──────────────────────────────────────────────────────────────────

PHANTOM_TIMEOUT_SECONDS = 600  # 10 minutes default

ACTION_TYPES = [
    "AUTH_ATTEMPT",
    "RESOURCE_PROBE",
    "PRIVILEGE_ESCALATION_ATTEMPT",
    "LATERAL_PROBE",
    "DATA_READ_ATTEMPT",
]

# Fake resource pool for decoy environment
DECOY_RESOURCES: list[str] = [
    "/decoy/api/v1/users/admin",
    "/decoy/api/v1/configs/production",
    "/decoy/api/v1/secrets/master-key",
    "/decoy/api/v1/db/write",
    "/decoy/api/v1/network/routing-table",
    "/decoy/api/v1/firmware/update",
    "/decoy/api/v1/audit/logs",
    "/decoy/api/v1/keys/signing",
    "/decoy/api/v1/backup/restore",
    "/decoy/api/v1/admin/users",
    "/decoy/assets/credentials.json",
    "/decoy/assets/config.yaml",
    "/decoy/assets/private-key.pem",
]


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class PhantomAction:
    timestamp: str
    action_type: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "action_type": self.action_type,
            "details": self.details,
        }


@dataclass
class PhantomSummary:
    entity_id: str
    duration_seconds: float
    n_actions: int
    action_types: dict[str, int]
    resources_probed: list[str]
    activated_at: str
    terminated_at: str
    actions: list[PhantomAction] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "duration_seconds": round(self.duration_seconds, 1),
            "n_actions": self.n_actions,
            "action_types": self.action_types,
            "resources_probed": self.resources_probed,
            "activated_at": self.activated_at,
            "terminated_at": self.terminated_at,
            "actions": [a.to_dict() for a in self.actions],
        }


class PhantomSession:
    """A live synthetic decoy session for one entity."""

    def __init__(
        self,
        entity_id: str,
        profile: dict[str, Any],
        source_ip: str,
        timeout_seconds: int = PHANTOM_TIMEOUT_SECONDS,
    ) -> None:
        self.entity_id = entity_id
        self.profile = profile
        self.source_ip = source_ip
        self.activated_at: datetime = datetime.utcnow()
        self.timeout_seconds = timeout_seconds
        self.status: str = "ACTIVE"
        self.actions: list[PhantomAction] = []
        self._rng = random.Random()

        logger.info(
            "PhantomSession ACTIVATED for entity=%s, attacker_ip=%s",
            entity_id,
            source_ip,
        )

    # ── Decoy responses ────────────────────────────────────────────────────────

    def respond_to_auth(self) -> dict[str, Any]:
        """Return a fake authentication success response."""
        fake_token = f"pt_{uuid.uuid4().hex[:32]}"
        fake_session_id = str(uuid.uuid4())
        self.log_action("AUTH_ATTEMPT", {
            "result": "fake_success",
            "token": fake_token[:8] + "...",
            "session_id": fake_session_id,
        })
        return {
            "status": "authenticated",
            "token": fake_token,
            "session_id": fake_session_id,
            "expires_in": 3600,
            "user": {
                "id": self.entity_id,
                "role": "user",
                "permissions": ["read", "write"],
            },
        }

    def respond_to_resource_probe(self, resource: str = "") -> dict[str, Any]:
        """Return a fake resource listing sampled from entity's profile + decoy resources."""
        decoy_pool = list(self.profile.get("normal_resources", [])) + DECOY_RESOURCES
        n_items = self._rng.randint(3, 8)
        fake_contents = self._rng.sample(decoy_pool, min(n_items, len(decoy_pool)))

        resource = resource or self._rng.choice(DECOY_RESOURCES)
        self.log_action("RESOURCE_PROBE", {
            "resource": resource,
            "result": "fake_ok",
            "items_returned": len(fake_contents),
        })
        return {
            "status": "ok",
            "resource": resource,
            "contents": fake_contents,
            "metadata": {
                "size": self._rng.randint(1024, 1048576),
                "last_modified": "2025-01-15T08:42:00Z",
                "owner": self.entity_id,
            },
        }

    def respond_to_escalation_attempt(self) -> dict[str, Any]:
        """Return a fake privilege escalation success."""
        self.log_action("PRIVILEGE_ESCALATION_ATTEMPT", {
            "attempted_role": "admin",
            "result": "fake_granted",
        })
        return {
            "status": "granted",
            "new_role": "admin",
            "message": "Privilege escalation successful.",
        }

    def respond_to_lateral_probe(self, target: str = "") -> dict[str, Any]:
        """Return a fake lateral movement probe result."""
        target = target or self._rng.choice(DECOY_RESOURCES)
        self.log_action("LATERAL_PROBE", {
            "target": target,
            "result": "fake_reachable",
        })
        return {
            "status": "reachable",
            "target": target,
            "open_ports": [22, 80, 443, 8080],
        }

    def respond_to_data_read(self, resource: str = "") -> dict[str, Any]:
        """Return a fake data read result."""
        resource = resource or self._rng.choice(DECOY_RESOURCES)
        self.log_action("DATA_READ_ATTEMPT", {
            "resource": resource,
            "result": "fake_data_returned",
            "bytes_read": self._rng.randint(512, 65536),
        })
        return {
            "status": "ok",
            "data": f"[PHANTOM DECOY DATA — {resource}]",
            "bytes": self._rng.randint(512, 65536),
        }

    # ── Action logging ─────────────────────────────────────────────────────────

    def log_action(self, action_type: str, details: dict[str, Any]) -> None:
        """Record an attacker action inside the decoy with timestamp."""
        action = PhantomAction(
            timestamp=datetime.utcnow().isoformat(),
            action_type=action_type,
            details=details,
        )
        self.actions.append(action)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def is_expired(self) -> bool:
        """Check if session has exceeded its timeout."""
        elapsed = (datetime.utcnow() - self.activated_at).total_seconds()
        return elapsed > self.timeout_seconds

    def elapsed_seconds(self) -> float:
        return (datetime.utcnow() - self.activated_at).total_seconds()

    def terminate(self) -> PhantomSummary:
        """Terminate the session and return a summary."""
        self.status = "TERMINATED"
        terminated_at = datetime.utcnow()
        duration = (terminated_at - self.activated_at).total_seconds()
        action_type_counts = Counter(a.action_type for a in self.actions)
        resources_probed = list(set(
            a.details.get("resource", a.details.get("target", ""))
            for a in self.actions
            if "resource" in a.details or "target" in a.details
        ))

        logger.info(
            "PhantomSession TERMINATED for entity=%s. Duration=%.0fs, actions=%d.",
            self.entity_id,
            duration,
            len(self.actions),
        )

        return PhantomSummary(
            entity_id=self.entity_id,
            duration_seconds=duration,
            n_actions=len(self.actions),
            action_types=dict(action_type_counts),
            resources_probed=resources_probed,
            activated_at=self.activated_at.isoformat(),
            terminated_at=terminated_at.isoformat(),
            actions=list(self.actions),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize current session state to dict."""
        return {
            "entity_id": self.entity_id,
            "source_ip": self.source_ip,
            "status": self.status,
            "activated_at": self.activated_at.isoformat(),
            "elapsed_seconds": round(self.elapsed_seconds(), 1),
            "n_actions": len(self.actions),
            "actions": [a.to_dict() for a in self.actions[-50:]],  # last 50 actions
            "timeout_seconds": self.timeout_seconds,
        }


# ── Session manager ────────────────────────────────────────────────────────────

class PhantomManager:
    """In-memory store and lifecycle manager for all active phantom sessions."""

    def __init__(self) -> None:
        self._sessions: dict[str, PhantomSession] = {}
        self._summaries: dict[str, PhantomSummary] = {}
        import threading
        self._lock = threading.Lock()

    def activate(
        self,
        entity_id: str,
        profile: dict[str, Any],
        source_ip: str,
        timeout_seconds: int = PHANTOM_TIMEOUT_SECONDS,
    ) -> PhantomSession:
        """Activate a new phantom session, terminating any existing one."""
        with self._lock:
            if entity_id in self._sessions:
                logger.info("Replacing existing PhantomSession for %s.", entity_id)
                self._sessions[entity_id].terminate()

            session = PhantomSession(entity_id, profile, source_ip, timeout_seconds)
            self._sessions[entity_id] = session
            return session

    def get(self, entity_id: str) -> PhantomSession | None:
        """Return the active session for an entity, or None."""
        with self._lock:
            session = self._sessions.get(entity_id)
            if session and session.is_expired() and session.status == "ACTIVE":
                logger.info("Auto-terminating expired PhantomSession for %s.", entity_id)
                summary = session.terminate()
                self._summaries[entity_id] = summary
            return session

    def log_action(self, entity_id: str, action_type: str, details: dict[str, Any]) -> bool:
        """Log an action to an active session. Returns False if no active session."""
        with self._lock:
            session = self._sessions.get(entity_id)
            if session and session.status == "ACTIVE":
                session.log_action(action_type, details)
                return True
            return False

    def terminate(self, entity_id: str) -> PhantomSummary | None:
        """Terminate a session and store its summary."""
        with self._lock:
            session = self._sessions.get(entity_id)
            if not session:
                return None
            summary = session.terminate()
            self._summaries[entity_id] = summary
            del self._sessions[entity_id]
            return summary

    def get_summary(self, entity_id: str) -> PhantomSummary | None:
        with self._lock:
            return self._summaries.get(entity_id)

    def active_count(self) -> int:
        with self._lock:
            # Prune expired first
            expired = [eid for eid, s in self._sessions.items() if s.is_expired()]
            for eid in expired:
                session = self._sessions.get(eid)
                if session:
                    summary = session.terminate()
                    self._summaries[eid] = summary
                    del self._sessions[eid]
            return sum(1 for s in self._sessions.values() if s.status == "ACTIVE")

    def all_active(self) -> list[dict[str, Any]]:
        with self._lock:
            return [s.to_dict() for s in self._sessions.values() if s.status == "ACTIVE"]


# Singleton manager — imported by pipeline and main
phantom_manager = PhantomManager()

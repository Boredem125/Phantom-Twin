"""
schemas.py — Pydantic models for all PHANTOM TWIN API request/response bodies.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


# ── Input schemas ──────────────────────────────────────────────────────────────

class EventInput(BaseModel):
    """Raw access log event submitted to the pipeline."""

    entity_id: str = Field(..., min_length=1, max_length=128)
    entity_type: str = Field(..., pattern="^(user|service_account|edge_device)$")
    timestamp: str = Field(..., min_length=10)
    source_ip: str = Field(..., min_length=7, max_length=45)
    geo_location: str = Field(..., min_length=1, max_length=128)
    resource_accessed: str = Field(..., min_length=1, max_length=512)
    auth_method: str = Field(..., min_length=1, max_length=64)
    session_duration: float = Field(..., ge=0.0)
    command_sequence: str = Field(default="", max_length=2048)
    device_fingerprint: str = Field(..., min_length=1, max_length=128)

    @field_validator("entity_type")
    @classmethod
    def entity_type_valid(cls, v: str) -> str:
        valid = {"user", "service_account", "edge_device"}
        if v not in valid:
            raise ValueError(f"entity_type must be one of {valid}")
        return v


class PhantomActionInput(BaseModel):
    """Simulated attacker action to log into an active phantom session."""

    entity_id: str = Field(..., min_length=1)
    action_type: str = Field(..., pattern="^(AUTH_ATTEMPT|RESOURCE_PROBE|PRIVILEGE_ESCALATION_ATTEMPT|LATERAL_PROBE|DATA_READ_ATTEMPT)$")
    details: dict[str, Any] = Field(default_factory=dict)


class RagQueryInput(BaseModel):
    """Natural-language analyst question over live alert context."""

    question: str = Field(..., min_length=3, max_length=500)


# ── Output schemas ─────────────────────────────────────────────────────────────

class FeatureAttribution(BaseModel):
    """Per-feature deviation detail for one alert."""

    baseline: Any
    observed: Any
    delta: Any
    weight: float
    score: float


class PhantomActionOut(BaseModel):
    """Single attacker action in a phantom session."""

    timestamp: str
    action_type: str
    details: dict[str, Any]


class PhantomSessionOut(BaseModel):
    """Current state of a phantom session."""

    entity_id: str
    source_ip: str
    status: str
    activated_at: str
    elapsed_seconds: float
    n_actions: int
    actions: list[PhantomActionOut]
    timeout_seconds: int


class PhantomSummaryOut(BaseModel):
    """Summary returned after a phantom session is terminated."""

    entity_id: str
    duration_seconds: float
    n_actions: int
    action_types: dict[str, int]
    resources_probed: list[str]
    activated_at: str
    terminated_at: str
    actions: list[PhantomActionOut] = Field(default_factory=list)


class CoLabel(BaseModel):
    attack_type: str
    confidence: float


class AlertOut(BaseModel):
    """Enriched alert returned by the pipeline."""

    alert_id: str
    timestamp: str
    entity_id: str
    entity_type: str
    risk_score: float
    risk_level: str
    attack_type: str
    confidence: float
    explanation: str
    explanation_summary: str
    feature_attribution: dict[str, Any]
    co_labels: list[CoLabel] = Field(default_factory=list)
    profile_bootstrap: bool
    phantom_session: PhantomSessionOut | None = None
    phantom_activated: bool
    event: dict[str, Any]


class EntityProfileOut(BaseModel):
    """Entity behavioral profile summary."""

    entity_id: str
    entity_type: str
    peak_hour: float
    hour_sigma: float
    home_geos: list[str]
    normal_resources: list[str]
    avg_duration: float
    dur_sigma: float
    preferred_auth: str
    known_fingerprints: list[str]
    n_events: int
    bootstrap: bool


class SystemStatusOut(BaseModel):
    """Live system counters."""

    total_events_processed: int
    total_alerts: int
    active_phantom_sessions: int
    entities_monitored: int
    health: str  # NOMINAL | DEGRADED | OFFLINE


class RagQueryOut(BaseModel):
    """RAG answer returned to the dashboard."""

    question: str
    answer: str
    evidence: list[dict[str, Any]]
    pinecone_status: str
    generated_at: str


class ValidationErrorResponse(BaseModel):
    detail: str
    field: str | None = None


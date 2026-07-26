"""
synthetic_generator.py — Realistic synthetic event generator for PHANTOM TWIN.

Simulates 8 behaviour patterns:
  Normal baseline         – per-entity habitual logins with realistic noise
  BruteForce              – rapid repeated failed-auth burst from one IP
  ImpossibleTravel        – same entity from distant geo within short window
  CredentialStuffing      – many entity_ids, few source_ips, high failure rate
  LateralMovement         – unusual breadth of resources never touched before
  DeviceSpoofing          – known device_id with mismatched fingerprint
  LowAndSlowExfiltration  – small off-hours accesses building over time
  InsiderDrift            – gradual privilege expansion (edge case / FP tuning)

Calls process_event() directly (no HTTP) — zero connection issues.
Reads entity profiles from disk so events match the entity's known baseline.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger("synthetic_generator")

ENTITY_POOL = [f"ENT-{i:04d}" for i in range(1, 101)]

FOREIGN_CITIES = [
    "Lagos", "São Paulo", "Moscow", "Beijing",
    "Jakarta", "Bogotá", "Cairo", "Pyongyang", "Minsk",
]

LATERAL_RESOURCES = [
    "/api/v1/admin/users", "/api/v1/admin/keys",
    "/api/v1/network/routing-table", "/api/v1/infra/hosts",
    "/api/v1/secrets/master-key", "/api/v1/internal/billing",
    "/api/v1/data/pii", "/api/v1/logs/audit",
]

PRIVILEGED_RESOURCES = [
    "/api/v1/admin/users", "/api/v1/admin/roles",
    "/api/v1/billing/invoices", "/api/v1/internal/config",
]

# Stuffing uses a fixed tiny set of foreign IPs
_STUFFING_IPS: list[str] = []


def _make_foreign_ip() -> str:
    first = random.choice([45, 62, 77, 91, 103, 185, 194, 203, 212])
    return f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


# ─────────────────────────────────────────────────────────────────────────────
# Profile cache — reads REAL disk profiles so events match entity baselines
# ─────────────────────────────────────────────────────────────────────────────

_PROFILE_CACHE: dict[str, dict[str, Any]] = {}
_PROFILES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "backend", "data", "profiles",
)


def _load_disk_profile(entity_id: str) -> dict[str, Any] | None:
    """Load an entity profile from disk; returns None if not found."""
    if entity_id in _PROFILE_CACHE:
        return _PROFILE_CACHE[entity_id]
    path = os.path.join(_PROFILES_DIR, f"{entity_id}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        profile = json.load(f)
    _PROFILE_CACHE[entity_id] = profile
    return profile


def _entity_home_geo(entity_id: str) -> str:
    """Pick the entity's most-likely home geo from its disk profile."""
    profile = _load_disk_profile(entity_id)
    if profile:
        geo_weights = profile.get("geo_weights", {})
        if geo_weights:
            # Pick the highest-weight city (most common in training data)
            return max(geo_weights, key=lambda k: geo_weights[k])
        home_geos = profile.get("home_geos", [])
        if home_geos:
            return home_geos[0]
    # Fallback: deterministic from entity number
    cities = ["Mumbai", "London", "New York", "Berlin", "Singapore", "Toronto", "Dubai"]
    seed = int(entity_id.split("-")[-1])
    return cities[seed % len(cities)]


def _entity_fingerprint(entity_id: str) -> str:
    """Pick the entity's known fingerprint from disk profile."""
    profile = _load_disk_profile(entity_id)
    if profile:
        fps = profile.get("known_fingerprints", [])
        if fps:
            return fps[0]
    return f"fp-{entity_id}"


def _entity_resource(entity_id: str) -> str:
    """Pick a resource from the entity's normal set."""
    profile = _load_disk_profile(entity_id)
    if profile:
        resources = profile.get("normal_resources", [])
        if resources:
            return random.choice(resources[:8])
    return "/api/v1/home"


def _entity_auth(entity_id: str) -> str:
    """Return the entity's preferred auth method."""
    profile = _load_disk_profile(entity_id)
    if profile:
        return profile.get("preferred_auth", "password")
    return "password"


def _entity_peak_hour(entity_id: str) -> int:
    """Return the entity's peak login hour."""
    profile = _load_disk_profile(entity_id)
    if profile:
        return int(profile.get("peak_hour", 12))
    return 12


def _home_ip(entity_id: str) -> str:
    """Generate a stable-looking IP for the entity."""
    seed = int(entity_id.split("-")[-1])
    rng = random.Random(seed)
    a, b, c = rng.randint(10, 200), rng.randint(0, 255), rng.randint(0, 255)
    return f"{a}.{b}.{c}.{random.randint(1, 254)}"


def _at_hour(hour: int) -> str:
    t = datetime.utcnow().replace(
        hour=hour % 24,
        minute=random.randint(0, 59),
        second=random.randint(0, 59),
        microsecond=0,
    )
    return t.isoformat()


def _now() -> str:
    return datetime.utcnow().isoformat()


# ─────────────────────────────────────────────────────────────────────────────
# Event builders — all events conform exactly to EventInput schema
# ─────────────────────────────────────────────────────────────────────────────

def _normal_event(entity_id: str) -> dict[str, Any]:
    """Benign event: matches entity's known city, fingerprint, resource, auth."""
    peak = _entity_peak_hour(entity_id)
    hour = max(0, min(23, peak + random.randint(-2, 2)))
    return {
        "entity_id":          entity_id,
        "entity_type":        "user",
        "timestamp":          _at_hour(hour),
        "source_ip":          _home_ip(entity_id),
        "geo_location":       _entity_home_geo(entity_id),
        "resource_accessed":  _entity_resource(entity_id),
        "auth_method":        _entity_auth(entity_id),
        "session_duration":   round(random.uniform(4.0, 45.0), 2),
        "command_sequence":   "",
        "device_fingerprint": _entity_fingerprint(entity_id),
    }


def _brute_force_event(entity_id: str, attacker_ip: str) -> dict[str, Any]:
    attempts = random.randint(15, 50)
    return {
        "entity_id":          entity_id,
        "entity_type":        "user",
        "timestamp":          _now(),
        "source_ip":          attacker_ip,
        "geo_location":       random.choice(FOREIGN_CITIES),
        "resource_accessed":  "/api/v1/auth/login",
        "auth_method":        "password",
        "session_duration":   0.0,
        "command_sequence":   f"failed_attempts={attempts}",
        "device_fingerprint": f"fp-scanner-{random.randint(1000,9999)}",
    }


def _impossible_travel_pair(entity_id: str) -> list[dict[str, Any]]:
    home_geo = _entity_home_geo(entity_id)
    foreign  = random.choice([c for c in FOREIGN_CITIES])
    t1 = datetime.utcnow()
    t2 = t1 + timedelta(minutes=random.randint(6, 20))
    return [
        {
            "entity_id":          entity_id,
            "entity_type":        "user",
            "timestamp":          t1.isoformat(),
            "source_ip":          _home_ip(entity_id),
            "geo_location":       home_geo,
            "resource_accessed":  _entity_resource(entity_id),
            "auth_method":        _entity_auth(entity_id),
            "session_duration":   round(random.uniform(1.0, 5.0), 2),
            "command_sequence":   "",
            "device_fingerprint": _entity_fingerprint(entity_id),
        },
        {
            "entity_id":          entity_id,
            "entity_type":        "user",
            "timestamp":          t2.isoformat(),
            "source_ip":          _make_foreign_ip(),
            "geo_location":       foreign,
            "resource_accessed":  "/api/v1/auth/login",
            "auth_method":        "password",
            "session_duration":   0.0,
            "command_sequence":   "geo_impossible=true",
            "device_fingerprint": f"fp-unknown-{random.randint(1000,9999)}",
        },
    ]


def _stuffing_event() -> dict[str, Any]:
    global _STUFFING_IPS
    if not _STUFFING_IPS:
        _STUFFING_IPS = [_make_foreign_ip() for _ in range(4)]
    entity_id = random.choice(ENTITY_POOL)
    return {
        "entity_id":          entity_id,
        "entity_type":        "user",
        "timestamp":          _now(),
        "source_ip":          random.choice(_STUFFING_IPS),
        "geo_location":       random.choice(FOREIGN_CITIES),
        "resource_accessed":  "/api/v1/auth/login",
        "auth_method":        "password",
        "session_duration":   0.0,
        "command_sequence":   "stuffing=true,tool=snipr",
        "device_fingerprint": f"fp-bot-{random.randint(100, 999)}",
    }


def _lateral_event(entity_id: str) -> dict[str, Any]:
    return {
        "entity_id":          entity_id,
        "entity_type":        "user",
        "timestamp":          _now(),
        "source_ip":          _home_ip(entity_id),
        "geo_location":       _entity_home_geo(entity_id),
        "resource_accessed":  random.choice(LATERAL_RESOURCES),
        "auth_method":        _entity_auth(entity_id),
        "session_duration":   round(random.uniform(0.1, 4.0), 2),
        "command_sequence":   "pivot=true,recon=true",
        "device_fingerprint": _entity_fingerprint(entity_id),
    }


def _spoofing_event(entity_id: str) -> dict[str, Any]:
    real_fp = _entity_fingerprint(entity_id)
    # Mutate the fingerprint slightly to simulate a spoofed device
    fake_fp = real_fp + f"-spoof{random.randint(10,99)}"
    return {
        "entity_id":          entity_id,
        "entity_type":        "user",
        "timestamp":          _now(),
        "source_ip":          _home_ip(entity_id),
        "geo_location":       _entity_home_geo(entity_id),
        "resource_accessed":  _entity_resource(entity_id),
        "auth_method":        _entity_auth(entity_id),
        "session_duration":   round(random.uniform(1.0, 10.0), 2),
        "command_sequence":   "fp_mismatch=true",
        "device_fingerprint": fake_fp,
    }


def _low_slow_event(entity_id: str) -> dict[str, Any]:
    return {
        "entity_id":          entity_id,
        "entity_type":        "user",
        "timestamp":          _at_hour(random.randint(1, 4)),
        "source_ip":          _home_ip(entity_id),
        "geo_location":       _entity_home_geo(entity_id),
        "resource_accessed":  random.choice(["/api/v1/data/export",
                                              "/api/v1/reports",
                                              "/api/v1/logs/audit"]),
        "auth_method":        "api_key",
        "session_duration":   round(random.uniform(0.05, 1.5), 2),
        "command_sequence":   "off_hours=true,exfil=low",
        "device_fingerprint": _entity_fingerprint(entity_id),
    }


def _insider_event(entity_id: str) -> dict[str, Any]:
    peak = _entity_peak_hour(entity_id)
    hour = max(0, min(23, peak + random.randint(-1, 3)))
    resource = (
        _entity_resource(entity_id)
        if random.random() < 0.55
        else random.choice(PRIVILEGED_RESOURCES)
    )
    return {
        "entity_id":          entity_id,
        "entity_type":        "user",
        "timestamp":          _at_hour(hour),
        "source_ip":          _home_ip(entity_id),
        "geo_location":       _entity_home_geo(entity_id),
        "resource_accessed":  resource,
        "auth_method":        _entity_auth(entity_id),
        "session_duration":   round(random.uniform(5.0, 35.0), 2),
        "command_sequence":   "privilege_drift=gradual",
        "device_fingerprint": _entity_fingerprint(entity_id),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Behaviour schedule
# ─────────────────────────────────────────────────────────────────────────────

BEHAVIOURS = [
    ("Normal",                75),   # most events are benign
    ("BruteForce",             4),
    ("ImpossibleTravel",       3),
    ("CredentialStuffing",     4),
    ("LateralMovement",        5),
    ("DeviceSpoofing",         4),
    ("LowAndSlowExfiltration", 3),
    ("InsiderDrift",           2),
]
_B_NAMES   = [b[0] for b in BEHAVIOURS]
_B_WEIGHTS = [b[1] for b in BEHAVIOURS]

# How many phantom sessions we allow to be open simultaneously
MAX_PHANTOM = 5


# ─────────────────────────────────────────────────────────────────────────────
# Generator
# ─────────────────────────────────────────────────────────────────────────────

class SyntheticGenerator:
    """
    Generates realistic synthetic events and processes them in-process.

    Key design decisions:
    - Calls pipeline.process_event() directly (no HTTP → zero connection errors).
    - Reads disk profiles so event attributes match entity baselines → correct
      risk distribution (normal events score LOW, attacks score HIGH/CRITICAL).
    - Caps concurrent phantom sessions at MAX_PHANTOM to keep logs readable.
    - Uses human-paced intervals to keep the UI readable.
    """

    def __init__(self) -> None:
        self.running: bool = True
        self._process_fn: Any = None

    def _pipeline(self) -> Any:
        if self._process_fn is None:
            from backend.pipeline import process_event
            self._process_fn = process_event
        return self._process_fn

    async def _emit(self, event: dict[str, Any]) -> None:
        try:
            process_fn = self._pipeline()
            loop = asyncio.get_event_loop()
            # run_in_executor(None, callable, *args) — runs sync fn in thread pool
            alert = await loop.run_in_executor(None, process_fn, event)
        except Exception as exc:
            logger.debug("Pipeline error: %s", exc)
            return

        # Yield control back to the event loop before doing any more work
        await asyncio.sleep(0)

        newly = event.get("_newly_activated", False)
        if newly:
            pass

        try:
            from backend.main import _broadcast_alert, _record_alert
            _record_alert(alert)
            await _broadcast_alert(alert)
        except Exception as exc:
            logger.debug("Broadcast skip: %s", exc)

        if newly:
            try:
                from backend.main import _simulate_generic_phantom_activity
                asyncio.create_task(
                    _simulate_generic_phantom_activity(event["entity_id"])
                )
            except Exception:
                pass

    async def run(self) -> None:
        # Brief pause so FastAPI shared state is fully initialized
        await asyncio.sleep(0.5)
        logger.info("SyntheticGenerator loop started.")

        while self.running:
            try:
                entity    = random.choice(ENTITY_POOL)
                behaviour = random.choices(_B_NAMES, _B_WEIGHTS)[0]

                if behaviour == "Normal":
                    await self._emit(_normal_event(entity))
                    await asyncio.sleep(random.uniform(0.5, 1.5))

                elif behaviour == "BruteForce":
                    attacker_ip = _make_foreign_ip()
                    target      = random.choice(ENTITY_POOL)
                    burst       = random.randint(6, 14)
                    for _ in range(burst):
                        await self._emit(_brute_force_event(target, attacker_ip))
                        await asyncio.sleep(random.uniform(0.08, 0.25))
                    await asyncio.sleep(random.uniform(3.0, 8.0))

                elif behaviour == "ImpossibleTravel":
                    for ev in _impossible_travel_pair(entity):
                        await self._emit(ev)
                        await asyncio.sleep(0.6)
                    await asyncio.sleep(random.uniform(4.0, 10.0))

                elif behaviour == "CredentialStuffing":
                    batch = random.randint(8, 18)
                    for _ in range(batch):
                        await self._emit(_stuffing_event())
                        await asyncio.sleep(random.uniform(0.07, 0.2))
                    await asyncio.sleep(random.uniform(3.0, 8.0))

                elif behaviour == "LateralMovement":
                    await self._emit(_lateral_event(entity))
                    await asyncio.sleep(random.uniform(2.0, 5.0))

                elif behaviour == "DeviceSpoofing":
                    await self._emit(_spoofing_event(entity))
                    await asyncio.sleep(random.uniform(2.0, 5.0))

                elif behaviour == "LowAndSlowExfiltration":
                    await self._emit(_low_slow_event(entity))
                    await asyncio.sleep(random.uniform(4.0, 12.0))

                elif behaviour == "InsiderDrift":
                    await self._emit(_insider_event(entity))
                    await asyncio.sleep(random.uniform(3.0, 8.0))

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("SyntheticGenerator error: %s", exc, exc_info=True)
                await asyncio.sleep(2.0)

    async def stop(self) -> None:
        self.running = False
        logger.info("SyntheticGenerator stopped.")


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

synthetic_generator = SyntheticGenerator()


async def start_generator() -> None:
    asyncio.create_task(synthetic_generator.run())


async def stop_generator() -> None:
    await synthetic_generator.stop()

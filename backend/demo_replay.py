"""
demo_replay.py — Scripted demo replay for PHANTOM TWIN judges.

Streams test.csv events through the pipeline at configurable speed,
broadcasts results via WebSocket, and prints progress to stdout.

Demonstrates all 7 demo scenario steps from MASTER_PROMPT.md.

Usage:
    python backend/demo_replay.py --delay 0.2
    python backend/demo_replay.py --delay 0.05 --max_events 500
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from typing import Any

import pandas as pd
import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("demo_replay")

API_BASE = "http://localhost:8000"


def send_event(event: dict[str, Any], client: httpx.Client) -> dict[str, Any] | None:
    """POST a single event to the pipeline API."""
    try:
        resp = client.post(f"{API_BASE}/api/event", json=event, timeout=10.0)
        if resp.status_code == 200:
            return resp.json()
        logger.warning("API returned %d: %s", resp.status_code, resp.text[:200])
        return None
    except Exception as exc:
        logger.error("Failed to send event: %s", exc)
        return None


def run_replay(
    test_csv: str = "backend/data/test.csv",
    delay: float = 0.2,
    max_events: int | None = None,
) -> None:
    """Stream events from test.csv through the live API."""
    if not os.path.exists(test_csv):
        logger.error("Test CSV not found: %s. Run generator first.", test_csv)
        sys.exit(1)

    df = pd.read_csv(test_csv)
    if max_events:
        df = df.head(max_events)

    total = len(df)
    logger.info("Starting demo replay: %d events at %.2fs delay.", total, delay)
    logger.info("Connect dashboard to %s/ws/alerts", API_BASE)
    print("\n" + "=" * 60)
    print("  PHANTOM TWIN — DEMO REPLAY")
    print("=" * 60)

    alerts_fired = 0
    phantoms_active = 0
    critical_fired = 0

    with httpx.Client() as client:
        for i, (_, row) in enumerate(df.iterrows()):
            event = row.to_dict()
            # Remove label if present (it's test data)
            event.pop("label", None)

            # Clean NaN
            event = {k: ("" if (isinstance(v, float) and str(v) == "nan") else v)
                     for k, v in event.items()}
            # Ensure float session_duration
            try:
                event["session_duration"] = float(event.get("session_duration", 15.0))
            except (ValueError, TypeError):
                event["session_duration"] = 15.0

            alert = send_event(event, client)

            if alert:
                level = alert.get("risk_level", "LOW")
                atype = alert.get("attack_type", "normal")

                if level in ("HIGH", "CRITICAL") or atype != "normal":
                    alerts_fired += 1
                if alert.get("phantom_activated"):
                    phantoms_active += 1
                if level == "CRITICAL":
                    critical_fired += 1
                    print(f"\n🚨 CRITICAL ALERT — {atype.upper()} on {alert['entity_id']}")
                    print(f"   {alert.get('explanation_summary', '')}")
                    if alert.get("phantom_activated"):
                        print(f"   ⚡ PHANTOM TWIN ACTIVATED")

            if i % 100 == 0 and i > 0:
                print(
                    f"  Event {i:>5}/{total} | Alerts: {alerts_fired:>4} | "
                    f"Criticals: {critical_fired:>3} | Active Phantoms: {phantoms_active:>2}"
                )

            time.sleep(delay)

    print("\n" + "=" * 60)
    print(f"  Replay complete: {total} events processed")
    print(f"  Alerts fired:    {alerts_fired}")
    print(f"  Critical alerts: {critical_fired}")
    print(f"  Phantom sessions activated: {phantoms_active}")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PHANTOM TWIN — Demo replay")
    parser.add_argument("--test", type=str, default="backend/data/test.csv")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between events in seconds")
    parser.add_argument("--max_events", type=int, default=None, help="Max events to replay (None = all)")
    args = parser.parse_args()

    run_replay(args.test, args.delay, args.max_events)

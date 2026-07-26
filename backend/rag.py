"""
rag.py - Pinecone-ready investigation layer for PHANTOM TWIN.

The dashboard needs to answer analyst questions over live alerts and decoy
activity. Pinecone is used when configured, and the same interface falls back
to a local deterministic store for hackathon demos without API keys.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from collections import Counter
from datetime import datetime
from typing import Any

logger = logging.getLogger("rag")

EMBED_DIMENSION = 128
PINECONE_INDEX_NAME = os.getenv("PINECONE_INDEX_NAME", "phantom-twin-rag")


def _stable_embedding(text: str) -> list[float]:
    """Return a deterministic lightweight embedding for local/Pinecone demos."""
    vector = [0.0] * EMBED_DIMENSION
    for token in re.findall(r"[a-z0-9_./:-]+", text.lower()):
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        idx = int.from_bytes(digest[:2], "big") % EMBED_DIMENSION
        sign = 1.0 if digest[2] % 2 == 0 else -1.0
        vector[idx] += sign

    norm = sum(v * v for v in vector) ** 0.5
    if norm == 0:
        return vector
    return [round(v / norm, 6) for v in vector]


def alert_to_document(alert: dict[str, Any]) -> dict[str, Any]:
    """Convert an alert to a compact retrieval document."""
    event = alert.get("event", {})
    action_count = 0
    if alert.get("phantom_session"):
        action_count = len(alert["phantom_session"].get("actions", []))

    text = (
        f"{alert.get('timestamp')} {alert.get('entity_id')} "
        f"{alert.get('entity_type')} {alert.get('risk_level')} "
        f"{alert.get('attack_type')} from {event.get('geo_location')} "
        f"source {event.get('source_ip')} resource {event.get('resource_accessed')} "
        f"phantom_actions {action_count}. {alert.get('explanation', '')}"
    )
    return {
        "id": str(alert.get("alert_id", hashlib.md5(text.encode("utf-8")).hexdigest())),
        "text": text,
        "metadata": {
            "entity_id": alert.get("entity_id"),
            "entity_type": alert.get("entity_type"),
            "risk_level": alert.get("risk_level"),
            "attack_type": alert.get("attack_type"),
            "geo_location": event.get("geo_location"),
            "source_ip": event.get("source_ip"),
            "resource": event.get("resource_accessed"),
            "timestamp": alert.get("timestamp"),
            "phantom_activated": alert.get("phantom_activated", False),
        },
    }


class InvestigationRag:
    """Small RAG facade with optional Pinecone upsert/query support."""

    def __init__(self) -> None:
        self._local_docs: dict[str, dict[str, Any]] = {}
        self._index: Any = None
        self._pinecone_error: str | None = None
        self._connect_pinecone()

    @property
    def pinecone_status(self) -> str:
        if self._index is not None:
            return "connected"
        if self._pinecone_error:
            return f"local_fallback: {self._pinecone_error}"
        return "local_fallback: PINECONE_API_KEY not set"

    def _connect_pinecone(self) -> None:
        api_key = os.getenv("PINECONE_API_KEY")
        if not api_key:
            return
        try:
            from pinecone import Pinecone

            pc = Pinecone(api_key=api_key)
            self._index = pc.Index(PINECONE_INDEX_NAME)
            logger.info("Connected to Pinecone index %s.", PINECONE_INDEX_NAME)
        except Exception as exc:
            self._pinecone_error = str(exc)
            self._index = None
            logger.warning("Pinecone unavailable, using local RAG fallback: %s", exc)

    def upsert_alerts(self, alerts: list[dict[str, Any]]) -> dict[str, Any]:
        docs = [alert_to_document(alert) for alert in alerts]
        for doc in docs:
            self._local_docs[doc["id"]] = doc

        if self._index is not None and docs:
            try:
                vectors = [
                    {
                        "id": doc["id"],
                        "values": _stable_embedding(doc["text"]),
                        "metadata": {**doc["metadata"], "text": doc["text"][:3500]},
                    }
                    for doc in docs
                ]
                self._index.upsert(vectors=vectors)
            except Exception as exc:
                self._pinecone_error = str(exc)
                logger.warning("Pinecone upsert failed, local store retained: %s", exc)

        return {"indexed": len(docs), "pinecone_status": self.pinecone_status}

    def query(
        self,
        question: str,
        alerts: list[dict[str, Any]],
        active_phantoms: list[dict[str, Any]],
        summaries: list[dict[str, Any]],
    ) -> dict[str, Any]:
        self.upsert_alerts(alerts)
        q = question.lower().strip()
        
        # 1. Retrieve the exact subset of matching alerts (pointers)
        evidence = self._retrieve_evidence(q, alerts)
        
        # 2. Try to get a natural response using Groq LLM
        answer = self._call_groq(question, evidence, active_phantoms)
        
        # 3. If Groq is offline or unavailable, use our high-quality heuristic direct answer
        if not answer:
            answer = self._heuristic_answer(q, evidence, active_phantoms, summaries)

        # Map back to UI evidence format (just return the raw alert dictionaries so UI can render them)
        return {
            "question": question,
            "answer": answer,
            "evidence": evidence[:8],
            "pinecone_status": self.pinecone_status,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def _retrieve_evidence(self, q: str, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        matched = []
        q_clean = q.lower()
        
        # Match by attack types
        if "stuffing" in q_clean or "credential" in q_clean:
            matched = [a for a in alerts if a.get("attack_type") == "credential_stuffing"]
        elif "brute" in q_clean or "force" in q_clean:
            matched = [a for a in alerts if a.get("attack_type") == "brute_force"]
        elif "travel" in q_clean or "impossible" in q_clean:
            matched = [a for a in alerts if a.get("attack_type") == "impossible_travel"]
        elif "lateral" in q_clean or "pivot" in q_clean:
            matched = [a for a in alerts if a.get("attack_type") == "lateral_movement"]
        elif "spoof" in q_clean or "fingerprint" in q_clean:
            matched = [a for a in alerts if a.get("attack_type") == "device_spoofing"]
        elif "exfil" in q_clean or "slow" in q_clean or "off-hour" in q_clean:
            matched = [a for a in alerts if a.get("attack_type") == "low_slow_exfiltration"]
        elif "insider" in q_clean or "drift" in q_clean:
            matched = [a for a in alerts if a.get("attack_type") == "insider_drift"]
        
        # Match by geo / location
        if not matched:
            india_terms = {"india", "mumbai", "delhi", "chennai", "bangalore", "hyderabad", "pune"}
            if "india" in q_clean:
                matched = [
                    a for a in alerts
                    if str(a.get("event", {}).get("geo_location", "")).lower() in india_terms
                ]
            else:
                # General geo matches
                geo_match = re.search(r"from\s+([a-zA-Z _-]+)", q_clean)
                if geo_match:
                    geo = geo_match.group(1).strip().split(" or ")[0]
                    matched = [
                        a for a in alerts
                        if geo in str(a.get("event", {}).get("geo_location", "")).lower()
                    ]

        # If still no match, fallback to semantic or most recent alerts
        if not matched:
            matches = self._semantic_matches(q, limit=5)
            # Find matching alerts in memory by ID
            match_ids = {m["id"] for m in matches}
            matched = [a for a in alerts if a.get("alert_id") in match_ids]

        # Fallback to high risk if empty
        if not matched:
            matched = [a for a in alerts if a.get("risk_level") in {"HIGH", "CRITICAL"}][:5]
            if not matched:
                matched = alerts[:5]

        return matched

    def _call_groq(self, question: str, evidence: list[dict[str, Any]], active_phantoms: list[dict[str, Any]]) -> str | None:
        api_key = os.getenv("GROQ_API_KEY") or os.getenv("GROK_API_KEY")
        if not api_key:
            return None
        
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        # Format clean context
        evidence_summary = []
        for a in evidence[:5]:
            ev = a.get("event", {})
            evidence_summary.append(
                f"- Alert {a.get('alert_id')}: Entity {a.get('entity_id')} ({a.get('risk_level')}) flagged for {a.get('attack_type')}. "
                f"IP: {ev.get('source_ip')}, Geo: {ev.get('geo_location')}, Resource: {ev.get('resource_accessed')}."
            )
        evidence_str = "\n".join(evidence_summary) if evidence_summary else "No matching alerts found."

        phantom_summary = []
        for p in active_phantoms[:3]:
            phantom_summary.append(
                f"- Decoy session ACTIVE for {p.get('entity_id')} from attacker IP {p.get('source_ip')}."
            )
        phantom_str = "\n".join(phantom_summary) if phantom_summary else "No active decoy sessions."

        prompt = (
            "You are PHANTOM TWIN's AI Resident Security Analyst.\n"
            f"An analyst has asked: \"{question}\"\n\n"
            "Here is the retrieved evidence from our logs:\n"
            f"{evidence_str}\n\n"
            "Active Decoy sessions:\n"
            f"{phantom_str}\n\n"
            "Provide a concise, professional, and natural response directly answering the analyst. "
            "Refer directly to specific entities (e.g. ENT-0010) or IPs if relevant. "
            "Keep the explanation clear, action-oriented, and under 3-4 sentences. Do not include markdown headers or lists."
        )

        data = {
            "model": "llama-3.1-8b-instant",
            "messages": [
                {"role": "system", "content": "You are a helpful, professional cybersecurity analyst."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "max_tokens": 250
        }

        try:
            import httpx
            resp = httpx.post(url, headers=headers, json=data, timeout=6.0)
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"].strip()
            else:
                logger.warning("Groq API returned status %d: %s", resp.status_code, resp.text)
        except Exception as exc:
            logger.warning("Failed to call Groq API: %s", exc)
        return None

    def _heuristic_answer(
        self,
        q_clean: str,
        evidence: list[dict[str, Any]],
        active_phantoms: list[dict[str, Any]],
        summaries: list[dict[str, Any]],
    ) -> str:
        # Fallback heuristic responses
        if "stuffing" in q_clean or "credential" in q_clean:
            matched = [a for a in evidence if a.get("attack_type") == "credential_stuffing"]
            if matched:
                ips = list(set(a.get("event", {}).get("source_ip", "") for a in matched))
                entities = list(set(a.get("entity_id", "") for a in matched))
                return f"Yes, credential stuffing has been detected. I flagged {len(matched)} matching attempts from IP(s) {', '.join(ips[:2])} targeting multiple credentials (such as {', '.join(entities[:3])})."
            return "No credential stuffing attacks are present in the current incident stream."

        if "travel" in q_clean or "impossible" in q_clean:
            matched = [a for a in evidence if a.get("attack_type") == "impossible_travel"]
            if matched:
                entities = list(set(a.get("entity_id", "") for a in matched))
                return f"Yes, impossible travel anomalies were detected for {', '.join(entities[:2])} logging in from geographically implausible endpoints."
            return "No impossible travel violations have been observed in the current window."

        if "brute" in q_clean or "force" in q_clean:
            matched = [a for a in evidence if a.get("attack_type") == "brute_force"]
            if matched:
                entities = list(set(a.get("entity_id", "") for a in matched))
                return f"Yes, active brute force attacks are in progress against {', '.join(entities[:2])}. Decoy sessions have been activated for containment."
            return "No brute force login patterns have been detected."

        if "india" in q_clean:
            matched = [
                a for a in evidence
                if str(a.get("event", {}).get("geo_location", "")).lower() in {"india", "mumbai", "delhi", "chennai", "bangalore", "hyderabad", "pune"}
            ]
            if matched:
                return f"I found {len(matched)} security alerts matching Indian locations. Pointers to these records are listed below."
            return "No access anomalies originating from India-linked locations have been logged."

        if "privilege" in q_clean or "escalation" in q_clean:
            return f"Currently, {len(active_phantoms)} active decoys are in place, monitoring potential privilege escalation and lateral movement paths."

        if "phantom" in q_clean or "honeypot" in q_clean or "decoy" in q_clean:
            return f"Deception Engine: {len(active_phantoms)} active containment decoys are currently routing threat actor sessions."

        if evidence:
            attacks = Counter(a.get("attack_type", "unknown") for a in evidence)
            return f"I analyzed the live telemetry and found {len(evidence)} related security alerts. The dominant pattern observed is: {attacks.most_common(1)[0][0]}."

        return "No matching security events have been flagged in the current analysis window."

    def _semantic_matches(self, question: str, limit: int) -> list[dict[str, Any]]:
        if self._index is not None:
            try:
                result = self._index.query(
                    vector=_stable_embedding(question),
                    top_k=limit,
                    include_metadata=True,
                )
                return [
                    {"id": item["id"], "score": item.get("score", 0), "metadata": item.get("metadata", {})}
                    for item in result.get("matches", [])
                ]
            except Exception as exc:
                self._pinecone_error = str(exc)
                logger.warning("Pinecone query failed, using local similarity: %s", exc)

        q_vec = _stable_embedding(question)
        scored: list[tuple[float, dict[str, Any]]] = []
        for doc in self._local_docs.values():
            d_vec = _stable_embedding(doc["text"])
            score = sum(a * b for a, b in zip(q_vec, d_vec))
            scored.append((score, doc))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [
            {"id": doc["id"], "score": round(score, 4), "metadata": doc["metadata"]}
            for score, doc in scored[:limit]
            if score > 0
        ]


rag_engine = InvestigationRag()

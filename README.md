# 👻 PHANTOM TWIN

> **AI-Powered Behavioral Anomaly Detection + Active Deception Layer**  
> *A Honeywell Hackathon Submission*

---

## 📖 The Problem
Modern Security Operations Centers (SOCs) face two massive challenges:
1. **Alert Fatigue:** Analysts are drowning in false positives from rigid, static threshold rules. 
2. **Reactive Containment:** When a true positive is detected, containing the threat requires manual intervention or heavy-handed automated bans (which risk disrupting legitimate business operations if they are false positives).

## 💡 Our Solution
**PHANTOM TWIN** is an end-to-end security platform that shifts the paradigm from purely reactive blocking to **Active Deception**.

Instead of just flagging anomalies, Phantom Twin continuously learns the baseline behavior of every entity (user or device). When critical deviations occur, it doesn't just block the attacker—it **silently routes them into a synthetic honeypot decoy (The Phantom Twin)**. The attacker believes they have successfully breached the system, while the platform safely logs their lateral movement, privilege escalation, and resource probes in an isolated environment.

### 🌟 Key Features
- **🧠 Behavioral Profiling:** Automatically builds baseline profiles (Geo-locations, peak hours, resource clusters, device fingerprints) for every entity using historical data.
- **🕵️ Sequence-Aware Detection:** Utilizes an Isolation Forest for point-in-time anomaly detection, paired with a stateful sliding-window heuristic engine to catch sequence-based attacks (e.g., Low and Slow, Insider Drift).
- **🕸️ Active Deception Layer:** Automatically spawns in-memory fake environments (decoys) for high-risk attackers. Contains the blast radius while gathering actionable threat intelligence.
- **🤖 Groq RAG AI Analyst:** A built-in natural language assistant that explains *why* an alert was flagged (feature attribution) and can query the current threat landscape (e.g., "Summarize the brute force attacks from India").
- **📊 Real-time Analyst Dashboard:** A React + Tailwind dashboard featuring live threat streaming, entity histories, and a real-time view into the active Phantom decoy environments.

---

## 📈 Evaluation Metrics
We evaluated our detection pipeline on an imbalanced dataset containing normal traffic and injected attack patterns (Brute Force, Credential Stuffing, Lateral Movement, Impossible Travel, etc.). 

* **Accuracy:** 99%
* **Binary AUC-ROC (Normal vs Anomaly):** 0.9860
* **FPR at Top-1% Alert Budget:** 0.10% (with 90.2% Precision)

*(Full evaluation results and confusion matrix can be found in `backend/evaluate_results.txt`)*

---

## 🚀 Quick Start Guide

### 1. Install Backend Dependencies
```bash
pip install -r backend/requirements.txt
```
*(Ensure you set your `GROQ_API_KEY` in your environment variables for the AI Analyst).*

### 2. Generate Synthetic Data & Train
We provide a synthetic data generator that creates normal baseline traffic and injects attack sequences based on a realistic taxonomy.
```bash
# Generate train/test data
python backend/data/generator.py --n_entities 200 --n_events 50000 --seed 42

# Build statistical entity profiles
python backend/models/profiler.py --input backend/data/train.csv

# Train the Isolation Forest Model
python -c "from backend.models.detector import train_isolation_forest; train_isolation_forest('backend/data/train.csv')"
```

### 3. Start the Backend Server
```bash
uvicorn backend.main:app --reload --port 8000
```

### 4. Install & Start Frontend Dashboard
```bash
cd frontend
npm install
npm run dev
```
Dashboard available at: **http://localhost:5173**

---

## 🏗️ Architecture Flow

```text
raw event
    │
    ▼
profiler.py ──────► entity profile (JSON)
    │
    ▼
detector.py ──────► risk_score (0–100) + feature_deviations
    │
    ▼
classifier.py ────► attack_type + confidence (Stateful sequence rules)
    │
    ▼
explainer.py ─────► explanation text + feature attribution
    │
    ▼
phantom.py ───────► Spawns PhantomSession (if HIGH/CRITICAL)
    │
    ▼
pipeline.py ──────► enriched alert dict
    │
    ▼
main.py ──────────► FastAPI + WebSocket broadcast
    │
    ▼
dashboard ────────► React + Tailwind real-time UI + RAG Copilot
```

---

## 🎯 Attack Taxonomy & Detection Coverage

| Attack Type | Detection Method | Confidence |
|-------------|------------------|------------|
| `brute_force` | Stateful tracking of failed auths in 60s windows | 0.60–0.99 |
| `impossible_travel` | Geo-velocity / Haversine distance heuristics | 0.85–0.99 |
| `credential_stuffing` | Cross-entity tracking, source IP aggregation | 0.85 |
| `lateral_movement` | Novel resource expansion during single session | 0.70–0.97 |
| `device_spoofing` | Profiler fingerprint mismatch | 0.90 |
| `low_and_slow` | Off-hours sliding window aggregation (3+ days) | 0.75 |
| `insider_drift` | Business-hours resource expansion (7+ days) | 0.40–0.70 |

---

## 🛠️ Demo Capabilities
To demonstrate the platform for judges:
1. Open the dashboard.
2. Click **Run Attack** in the Investigation Panel.
3. This triggers a scripted brute-force login from Mumbai (`backend/main.py -> _run_live_attack_demo`).
4. Watch as the backend intercepts the attack, returns a *fake success*, and traps the attacker in the Phantom Twin.
5. You can view the live, simulated commands the attacker runs inside the decoy environment under the "Phantom Deception Active" pane. 
6. Ask the AI assistant questions about the attack in the chat bar!

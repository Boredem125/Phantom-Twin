# PHANTOM TWIN

> AI-Powered Behavioral Anomaly Detection + Active Deception Layer  
> Honeywell Hackathon Submission

---

## Quick Start

### 1. Install Backend Dependencies
```bash
pip install -r backend/requirements.txt
```

### 2. Generate Synthetic Data
```bash
python backend/data/generator.py --n_entities 200 --n_events 50000 --seed 42
```
Outputs: `backend/data/train.csv`, `test.csv`, `labels_test.csv`

### 3. Build Entity Profiles
```bash
python backend/models/profiler.py --input backend/data/train.csv
```
Outputs: one JSON file per entity in `backend/data/profiles/`

### 4. Train Isolation Forest
```python
from backend.models.detector import train_isolation_forest
train_isolation_forest("backend/data/train.csv")
```
Outputs: `backend/models/iso_forest.pkl`, `backend/models/scaler.pkl`

### 5. Test the Pipeline
```bash
python backend/pipeline.py --event backend/data/sample_events/brute_force.json
```
Expected: `risk_score > 85`, `attack_type = "brute_force"`, `phantom_session != null`

### 6. Start the Backend Server
```bash
uvicorn backend.main:app --reload --port 8000
```

### 7. Install & Start Frontend
```bash
cd frontend
npm install
npm run dev
```
Dashboard available at: http://localhost:5173

### 8. Run Demo Replay (for judges)
```bash
python backend/demo_replay.py --delay 0.2
```

### 9. Run Evaluation
```bash
python backend/evaluate.py \
  --test backend/data/test.csv \
  --labels backend/data/labels_test.csv
```

---

## Architecture

```
raw event
    │
    ▼
profiler.py ──────► entity profile (JSON)
    │
    ▼
detector.py ──────► risk_score (0–100) + feature_deviations
    │
    ▼
classifier.py ────► attack_type + confidence
    │
    ▼
explainer.py ─────► explanation text + feature attribution
    │
    ▼
phantom.py ───────► PhantomSession (if HIGH/CRITICAL)
    │
    ▼
pipeline.py ──────► enriched alert dict
    │
    ▼
main.py ──────────► FastAPI + WebSocket broadcast
    │
    ▼
dashboard ────────► React + Tailwind real-time UI
```

---

## Project Structure

```
phantom-twin/
├── backend/
│   ├── data/
│   │   ├── generator.py          # Synthetic data generator
│   │   ├── profiles/             # Per-entity JSON profiles
│   │   ├── train.csv             # Training set
│   │   ├── test.csv              # Test set (labels hidden)
│   │   ├── labels_test.csv       # Held-out test labels
│   │   └── sample_events/        # One JSON per attack type
│   ├── models/
│   │   ├── profiler.py           # Entity behavioral profiler
│   │   ├── detector.py           # Isolation Forest + z-score
│   │   ├── classifier.py         # Rule-based attack classifier
│   │   ├── explainer.py          # NL explanation generator
│   │   ├── phantom.py            # Phantom Twin session manager
│   │   ├── iso_forest.pkl        # Trained model (generated)
│   │   └── scaler.pkl            # Feature scaler (generated)
│   ├── pipeline.py               # End-to-end event processor
│   ├── evaluate.py               # Metrics evaluation
│   ├── main.py                   # FastAPI server + WebSocket
│   ├── schemas.py                # Pydantic I/O models
│   ├── demo_replay.py            # Judge demo script
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/           # React dashboard components
│   │   ├── hooks/                # WebSocket + state hooks
│   │   ├── types/                # TypeScript interfaces
│   │   └── App.tsx
│   ├── tailwind.config.js        # Custom color tokens
│   └── package.json
├── report/
│   └── PHANTOM_TWIN_REPORT.md
└── README.md
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/event` | Process event through pipeline |
| GET | `/api/alerts?n=50` | Get last N alerts |
| GET | `/api/entity/{id}` | Entity profile + history |
| GET | `/api/phantom/{id}` | Active phantom session |
| POST | `/api/phantom/{id}/terminate` | Analyst terminates session |
| POST | `/api/demo/live-attack` | Start scripted fake-success honeypot demo |
| POST | `/api/rag/query` | Ask natural-language investigation questions |
| POST | `/api/rag/index` | Index current alerts into Pinecone/local RAG |
| GET | `/api/status` | Live system counters |
| WS | `/ws/alerts` | Real-time alert stream |


---

## Live Attack Demo + RAG

The dashboard now includes an investigation panel above the alert queue.

- Click `Run Attack` to trigger a live brute-force scenario from Mumbai. The attacker receives fake authentication success, but the backend activates a Phantom Twin honeypot and logs follow-on resource probes, privilege escalation, lateral movement, and data-read attempts.
- Ask natural-language questions such as `How many attempts from India?`, `How many privilege escalation possibilities?`, or `How many Phantom decoys are active?`.
- Pinecone is optional for the demo. Set `PINECONE_API_KEY` and `PINECONE_INDEX_NAME` to use a real index; otherwise the RAG layer uses a deterministic local fallback over the current alert window.

Pinecone setup uses the current SDK package:

```bash
pip install pinecone
set PINECONE_API_KEY=your_key_here
set PINECONE_INDEX_NAME=phantom-twin-rag
```
---

## Attack Patterns Detected

| Attack Type | Description | Confidence |
|-------------|-------------|------------|
| `brute_force` | 5+ failed auths in 60s from same IP | 0.60–0.99 |
| `impossible_travel` | Logins >2000km apart in <90 min | 0.85–0.99 |
| `credential_stuffing` | 10+ entities, ≤2 IPs, >70% failure | 0.85 |
| `lateral_movement` | 5+ novel resources in one session | 0.70–0.97 |
| `device_spoofing` | Unknown device fingerprint | 0.90 |
| `low_and_slow` | Off-hours small accesses over 3+ days | 0.75 |
| `insider_drift` | Business-hours resource expansion 7+ days | 0.40–0.70 |


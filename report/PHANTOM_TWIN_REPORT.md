# PHANTOM TWIN — Technical Report

## 1. System Overview

```
raw event (entity_id, timestamp, geo, resource, auth_method, device_fp, …)
    │
    ▼
┌────────────────────────────────────────────────────────────────────┐
│  PROFILER (profiler.py)                                             │
│  Per-entity statistical model built from training window            │
│  Cold-start: composite from 5 nearest peers by entity_type         │
└─────────────────────────────┬──────────────────────────────────────┘
                              │ profile dict
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│  DETECTOR (detector.py)                                             │
│  6 z-score features + Isolation Forest → composite risk score 0–100│
│  LOW < 40 | MEDIUM 40–70 | HIGH 70–85 | CRITICAL > 85              │
└─────────────────────────────┬──────────────────────────────────────┘
                              │ risk_score + feature_deviations
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│  CLASSIFIER (classifier.py)                                         │
│  Ordered rule-based: 7 attack patterns, multi-label, confidence     │
└─────────────────────────────┬──────────────────────────────────────┘
                              │ attack_type + confidence
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│  EXPLAINER (explainer.py)                                           │
│  NL text template + per-feature attribution table                   │
└─────────────────────────────┬──────────────────────────────────────┘
                              │ explanation_text + attribution
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│  PHANTOM TWIN (phantom.py) — activated on HIGH / CRITICAL          │
│  Generates live decoy session from entity's own profile             │
│  Logs attacker actions → feeds dashboard right pane                 │
└─────────────────────────────┬──────────────────────────────────────┘
                              │ PhantomSession
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│  PIPELINE (pipeline.py)                                             │
│  Chains all models, manages rolling event context                   │
└─────────────────────────────┬──────────────────────────────────────┘
                              │ enriched alert dict
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│  FastAPI (main.py)                                                  │
│  POST /api/event → WebSocket /ws/alerts → React dashboard           │
└────────────────────────────────────────────────────────────────────┘
```

---

## 2. Data Generation Assumptions

### Entity Population
- 200 entities: 100 users (50%), 50 service accounts (25%), 50 edge devices (25%)
- 50,000 normal events generated over a 90-day window
- Each entity has a unique behavioral profile — two users in the same role will have different login hours, geo sets, and resource preferences

### Per-Entity Normal Profile Parameters

| Parameter | Distribution | Notes |
|-----------|-------------|-------|
| Login hour | Gaussian(μ=9h, σ=1.5–2.5h) | User-specific, clipped [0, 23] |
| Geo location | Dirichlet-weighted set of 2–4 cities | Primary geo gets ~80% weight |
| Resource access | Markov chain over 5–15 resources | Transition matrix sampled from Dirichlet |
| Session duration | Gaussian(μ=25min, σ=3–8min) | Floored at 1 min |
| Auth method | 90% preferred, 10% other | Preferred sampled from [password, sso, api_key, cert, mfa] |
| Device fingerprint | 1–3 known UUIDs per entity | New fingerprint = spoofing |

### Attack Pattern Injection Rules

| Attack | Injection Rule | Label |
|--------|---------------|-------|
| brute_force | 5–20 failed auths in 60s, same source_ip | brute_force |
| impossible_travel | Two logins >2000km apart in ≤90 min | impossible_travel |
| credential_stuffing | 10–50 entity_ids, 1–2 IPs, >70% failure rate | credential_stuffing |
| lateral_movement | Access to 5+ resources never in entity's normal set, one session | lateral_movement |
| device_spoofing | Login with fingerprint not in entity's known set | device_spoofing |
| low_and_slow | 1–3 off-hours accesses/day (midnight–5am, 11pm+), 3–7 days | low_and_slow |
| insider_drift | Gradual resource expansion in business hours (9–17h), 7–14 days | insider_drift |

Injection rate: 0.5–3% of total events. Class imbalance preserved. Test anomaly rate target: 0.5–3%.

---

## 3. Model Choices and Rationale

### Isolation Forest (primary scorer)
- **Why**: Unsupervised, no labeled anomaly data needed for training. Handles high-dimensional feature spaces well. Works without oversampling on imbalanced datasets. O(n log n) inference — fast enough for streaming.
- **Why not LSTM**: Requires labeled sequences and significant more training data. Cold-start problem is worse for sequence models. Poor explainability.
- **Why not Autoencoder**: Similar rationale — higher complexity, harder to explain reconstruction error to analysts.

### Rule-Based Classifier
- **Why**: Interpretable and auditable. Each classification has a clear human-readable rationale that maps directly to the explanation template. Lower false positive rate for known attack patterns than a learned classifier on sparse anomaly labels.
- **Why not learned classifier**: With 0.5–3% anomaly rate, very few positive samples per class. A learned model would either overfit or require extensive SMOTE/ADASYN work that introduces its own artifacts.

### Composite Risk Score
- Formula: `risk = 0.40 × iso_forest_score + 0.60 × weighted_z_score`
- 60% weight on z-score because it's directly interpretable and maps to specific feature explanations
- 40% weight on Isolation Forest as a corroborating "global anomalousness" signal
- Bootstrap entities capped at 60% of computed score to avoid false positives on new entities

---

## 4. Evaluation Metrics

Per-class Precision / Recall / F1:
                     precision    recall  f1-score   support

        brute_force       1.00      0.71      0.83        14
credential_stuffing       0.89      0.73      0.80        33
    device_spoofing       0.11      1.00      0.20         1
  impossible_travel       0.00      1.00      0.00         1
      insider_drift       0.00      0.00      0.00         4
   lateral_movement       0.24      0.67      0.35         9
       low_and_slow       0.00      0.00      0.00         6
             normal       1.00      0.58      0.74      5084

           accuracy                           0.58      5152
          macro avg       0.40      0.59      0.37      5152
       weighted avg       0.99      0.58      0.73      5152

Binary AUC-ROC (normal vs anomaly): 0.9860

At top-1% score threshold (51 events):
  True Positives:  46
  False Positives: 5
  FPR:             0.0010 (0.10%)
  Precision:       0.9020 (90.20%)

---

## 5. Honeywell OT/ICS Applicability

The PHANTOM TWIN architecture maps directly to Honeywell OT/ICS protection scenarios:

### Edge Gateway Protection
- Each edge device (PLC, HMI, SCADA gateway) is an `edge_device` entity
- The profiler learns normal communication patterns: which PLCs talk to which resources, at what times, from which authenticated sessions
- Lateral movement detection catches reconnaissance attempts across the OT network

### Phantom Twin for PLCs
- When a compromised credential is used to access a PLC, PHANTOM TWIN activates a synthetic decoy environment
- The attacker receives plausible-looking (but entirely fake) sensor readings, register values, and command confirmations
- The real PLC continues operating safely while the SOC gets an alert and time to respond

### Cold-Start for New Devices
- New PLCs and edge devices get bootstrap profiles derived from peer devices of the same type
- Confidence is capped at 0.4 during the bootstrap period, preventing false alarms on commissioning traffic
- Bootstrap flag is visible in the dashboard

---

## 6. Known Limitations

1. **Sequence modeling**: The rule-based classifier does not model temporal sequences with memory. An LSTM or Transformer encoder on session command sequences would significantly improve recall for insider_drift and lateral_movement.

2. **Classifier false positives on normal drift**: Legitimate user behavioral changes (vacation, new role) can trigger insider_drift alerts. The concept drift mechanism (soft profile update at 0.1 rate) partially mitigates this but is not evaluated here.

3. **Phantom Twin is simulated, not networked**: The decoy session is a JSON simulation with fake responses. A production deployment would require a real honeypot infrastructure (e.g., OpenCanary, Cowrie) behind the phantom session.

4. **Rule-based classifier fails on novel variants**: A zero-day attack that doesn't match any of the 7 known patterns will be classified as "normal" with a high risk score but no specific attack type. A future hybrid approach would add a "suspicious_unclassified" fallback with a learned anomaly score.

5. **No real-time profile update**: Profiles are built from train.csv and static during inference. The concept drift update is documented but not wired to a background scheduler in this demo.

---

## 7. Scaling Path

### Streaming
- Replace CSV batch processing with **Apache Kafka** topic consumers
- Each Kafka consumer processes one event, runs `pipeline.process_event()`, publishes alert to output topic
- Dashboard subscribes to alert topic via WebSocket bridge (already implemented)

### Profile Store
- Replace local JSON files with **Redis** (RedisJSON module)
- Profile key: `profile:{entity_id}` — sub-millisecond reads
- Profile soft-updates written as atomic JSON patches
- Horizontal scaling: multiple pipeline workers all hit the same Redis cluster

### Isolation Forest at Scale
- Train per-entity-type models (3 models) rather than one shared model
- Alternatively, move to an online learning approach using **Half-Space Trees** (sklearn alternative) for streaming updates
- Model artifacts stored in S3 / GCS, loaded at worker startup

### Estimated throughput
- Single worker: ~2,000 events/sec (dominated by feature extraction)
- 10 workers behind Kafka: ~20,000 events/sec
- Adequate for most industrial OT environments (typical PLC telemetry: 100–1,000 events/sec)

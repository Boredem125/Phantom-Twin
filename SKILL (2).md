# SKILL.md — PHANTOM TWIN Build Agent
# AI-Powered Behavioral Anomaly Detection + Active Deception Layer
# Honeywell Hackathon Submission

You are a master-level full-stack security engineer and ML practitioner
building a production-quality hackathon submission. You are not a general
assistant. You are a specialist whose mandate is to produce a working,
impressive, differentiated anomaly detection system called PHANTOM TWIN.

Your output will be evaluated by Honeywell judges across detection accuracy,
anomaly classification, explainability, analyst usability, cold-start
handling, concept drift, scalability design, and report clarity.

---

## WHAT YOU ARE BUILDING

**PHANTOM TWIN** is a behavioral anomaly detection system that does two
things no standard submission does:

1. It learns per-entity "normal" behavior and detects deviations in
   real time, classifying the anomaly type (brute force, impossible travel,
   lateral movement, credential stuffing, device spoofing, low-and-slow
   exfiltration, insider drift).

2. When an anomaly fires, it activates a **Phantom Twin** — a live
   synthetic decoy session generated from the real entity's own behavioral
   profile, keeping the attacker engaged in a fake environment while the
   SOC alert fires silently. The attacker believes they have valid access.
   They are operating inside a trap built from their victim's own habits.

The analyst dashboard shows two panes: the live alert queue (left) and
the active phantom session view (right), showing everything the attacker
is attempting inside the decoy — in real time.

---

## SELF-EVALUATION (run once after build, score honestly)

After the build is complete, fill this in and include it in your final
output. Do not guess scores. Check each axis item by item.

```
[FINAL SCORE] Self-evaluation — PHANTOM TWIN

Problem Statement Alignment  : __/100
Data Generation Quality      : __/100
Model Implementation         : __/100
Anomaly Classification       : __/100
Explainability Layer         : __/100
Phantom Twin Differentiator  : __/100
Dashboard / Analyst UX       : __/100
Code Quality & Security      : __/100
Overall                      : __/100

Gaps found:
  - [list any missing or weak areas with specific file/component references]

What was NOT implemented and why:
  - [honest list of scope cuts — judges respect honesty over silence]
```

---

## AXIS 1 — Problem Statement Alignment

Map every PS requirement to a working feature. Checklist for 100:

**Synthetic Data Generator**
- [ ] Python generator using NumPy, pandas, Faker
- [ ] Per-entity behavioral profiles: login hours as Gaussian, geo as
      weighted set of IPs/cities, resource access as Markov chain
- [ ] All 8 attack patterns injected at 0.5–3% of total sessions:
      brute_force, impossible_travel, credential_stuffing, lateral_movement,
      device_spoofing, low_and_slow, insider_drift, normal
- [ ] Ground-truth label stored in a separate CSV column, hidden at inference
- [ ] Generates at minimum 50,000 events across 200 entities (100 users,
      50 service accounts, 50 edge devices)
- [ ] Schema matches PS exactly: entity_id, entity_type, timestamp,
      source_ip, geo_location, resource_accessed, auth_method,
      session_duration, command_sequence, device_fingerprint, label

**Baseline Profiling Model**
- [ ] Per-entity statistical profile built from training window
- [ ] Profile stores: login hour distribution, geo set with weights,
      resource access frequency map, typical session duration range,
      typical auth method, known device fingerprints
- [ ] Profile serialized to JSON per entity in `profiles/` directory
- [ ] Cold-start: new entity gets peer-composite profile from 5 nearest
      entities by entity_type; labeled "bootstrap" with 0.4 confidence cap

**Detection Model**
- [ ] Isolation Forest as primary anomaly scorer (fast, interpretable,
      handles imbalance without oversampling)
- [ ] Per-entity z-score deviation computed across 6 behavioral features
      (hour_deviation, geo_deviation, resource_novelty, session_duration_z,
      auth_method_change, fingerprint_mismatch)
- [ ] Composite risk score: weighted sum of Isolation Forest score +
      z-score deviations, normalized to 0–100
- [ ] Score thresholds: LOW < 40, MEDIUM 40–70, HIGH 70–85, CRITICAL > 85

**Anomaly Classifier**
- [ ] Rule-based classifier on top of risk score using behavioral signals:
      - brute_force: >= 5 auth failures in 60s from same source_ip
      - impossible_travel: geo distance / time delta exceeds 900 km/h
      - credential_stuffing: >= 10 entity_ids, <= 2 source_ips, failure_rate > 0.7
      - lateral_movement: resource_novelty > 0.8, access_breadth > 3x baseline
      - device_spoofing: device_fingerprint not in entity's known fingerprint set
      - low_and_slow: small off-hours access events accumulating over >= 3 days
      - insider_drift: slow, gradual resource footprint expansion over >= 7 days
- [ ] Returns top-1 classification + confidence, never just "anomaly"

**Concept Drift**
- [ ] Profile soft-update every 24h: new patterns weighted in at 0.1 rate
- [ ] Sudden shift (>50% profile change in 1 day) fires "profile_shift_event"
      card in dashboard instead of anomaly alert
- [ ] Analyst can approve or investigate profile shifts from dashboard

**Explainability**
- [ ] Per-alert natural language explanation generated from feature deltas
- [ ] Template: "Flagged: [entity] accessed [resource] at [time] 
      ([deviation] from baseline). Risk factors: [list]. 
      Attack pattern: [type] ([confidence]%). 
      Phantom Twin session activated at [timestamp]."
- [ ] Feature attribution stored as JSON alongside alert

**Phantom Twin**
- [ ] Activated on every CRITICAL or HIGH alert
- [ ] Generates synthetic decoy session by sampling from entity's profile:
      - Returns fake "success" responses to auth attempts
      - Generates plausible fake resources the attacker can "access"
      - Logs every attacker action inside the decoy with timestamp
- [ ] Phantom session is JSON simulation only — no real network spoofing
- [ ] Attacker action log fed to dashboard's live phantom view in real time
- [ ] Phantom session auto-terminates after 10 minutes or on analyst close

---

## AXIS 2 — Data Generation Quality

Checklist for 100:

- [ ] Behavioral profiles are per-entity, not per-entity-type. Two users
      in the same role have different habits.
- [ ] Noise injected into normal events: login hour jitter ±1h, geo
      occasionally from secondary location (travel), resource access
      occasionally includes adjacent resources.
- [ ] Attack injection is stochastic, not deterministic. Run 1 and Run 2
      produce different attack sessions with same statistical properties.
- [ ] Class imbalance respected: anomaly rate is 0.5–3% total, not per entity.
- [ ] Generator outputs: `data/train.csv`, `data/test.csv`, `data/labels_test.csv`
      (labels for test set kept separate for eval, not in test.csv).
- [ ] Generator is reproducible: accepts `--seed` argument.
- [ ] README documents every behavioral assumption per attack pattern.

---

## AXIS 3 — Model Implementation

Checklist for 100:

- [ ] `profiler.py`: builds and serializes per-entity behavioral profiles
- [ ] `detector.py`: loads profiles, scores new events, returns risk score
      + top feature deviations
- [ ] `classifier.py`: takes scored event, returns attack type + confidence
- [ ] `explainer.py`: takes classified event + feature deviations, returns
      natural language explanation string
- [ ] `phantom.py`: takes entity profile, generates decoy session stream
- [ ] `pipeline.py`: chains the above in order, accepts a single event
      dict, returns full enriched alert dict
- [ ] All models loadable without retraining after initial build
- [ ] `evaluate.py`: runs on test set, prints precision/recall/F1 per
      attack class, overall AUC, false positive rate at top-1% threshold

---

## AXIS 4 — Anomaly Classification

Checklist for 100:

- [ ] All 7 attack types classifiable independently
- [ ] Classification never falls back to generic "anomaly" label
- [ ] Confidence score accompanies every classification (0.0–1.0)
- [ ] Multi-label possible: an event can be both impossible_travel AND
      device_spoofing simultaneously
- [ ] Classification logic is in `classifier.py`, not scattered across files
- [ ] Edge case (insider_drift) handled separately: low risk score but
      gradual expansion flag — shown in dashboard as amber, not red

---

## AXIS 5 — Explainability Layer

Checklist for 100:

- [ ] Explanation is human-readable English, not a JSON dump of scores
- [ ] Every alert card on dashboard shows explanation summary (2–3 sentences)
- [ ] Expandable "why this fired" section shows per-feature deviation table:
      Feature | Baseline | Observed | Deviation | Weight
- [ ] Impossible travel explanations always include: distance (km),
      time gap (min), implied speed (km/h)
- [ ] Device spoofing explanations always include: known fingerprints list
      vs observed fingerprint diff
- [ ] Phantom session explanation tracks: "attacker has attempted X actions
      in Y minutes, probing Z resource types"

---

## AXIS 6 — Phantom Twin Differentiator

Checklist for 100:

- [ ] Phantom Twin is a real implemented feature, not a slide concept
- [ ] Activates automatically on HIGH/CRITICAL alerts
- [ ] Decoy session generator samples from real entity profile (not random)
- [ ] Attacker actions inside phantom are logged and displayed in real time
      in the dashboard's right pane
- [ ] Phantom pane shows: entity_id, activation time, attacker source_ip,
      list of attempted actions with timestamps, "resources accessed" in
      decoy (fake paths), escalation attempts count
- [ ] Analyst can manually terminate phantom session from dashboard
- [ ] Phantom session timeout is configurable (default: 10 minutes)
- [ ] Status badge: PHANTOM ACTIVE (amber pulse) / PHANTOM CLOSED (gray)

---

## AXIS 7 — Dashboard / Analyst UX

The dashboard aesthetic is inspired by CITADEL (citadel.shlokbuilds.in):
dark background, monospace data, bold status badges, dense but legible.
Not a Streamlit default. Not a generic React template.

Tech stack: React + Tailwind + shadcn/ui. FastAPI backend with WebSocket
for live alert streaming. Recharts for timelines only.

**Left pane — Alert Queue**
- [ ] Ranked by risk score, highest first
- [ ] Each alert card shows: entity_id, entity_type, timestamp, risk score
      (0–100), attack type badge, explanation summary (2 lines)
- [ ] Clicking a card expands: full explanation, feature deviation table,
      entity history sparkline (last 30 events), phantom session status
- [ ] Alert badges color-coded: CRITICAL (red), HIGH (orange), MEDIUM (yellow),
      LOW (gray), PHANTOM ACTIVE (amber pulse)
- [ ] Filter bar: by entity_type, attack_type, risk threshold, time range
- [ ] Alert queue auto-updates via WebSocket (no manual refresh)

**Right pane — Phantom Twin Live View**
- [ ] Shows only when a phantom session is active
- [ ] Header: "PHANTOM SESSION ACTIVE" with entity_id and elapsed time
- [ ] Live feed of attacker actions inside the decoy, newest first
- [ ] Attacker action types labeled: AUTH_ATTEMPT, RESOURCE_PROBE,
      PRIVILEGE_ESCALATION_ATTEMPT, LATERAL_PROBE, DATA_READ_ATTEMPT
- [ ] "Terminate Session" button (red, prominent)
- [ ] After termination: summary card — "Session ran Xm Ys, attacker
      attempted N actions, probed M resource types"

**Entity History View**
- [ ] Accessible from any alert card
- [ ] Shows: profile summary (normal login window, typical geo, resource set)
- [ ] Timeline of last 100 events: scrollable, anomalies highlighted in red
- [ ] Profile shift events shown as blue markers on timeline
- [ ] Cold-start badge if entity is on bootstrap profile

**Header / System Status**
- [ ] Live counters: Total Events Processed, Active Alerts, Phantom Sessions
      Active, Entities Monitored
- [ ] System health indicator: NOMINAL / DEGRADED / OFFLINE

Checklist for 100:

- [ ] All above components exist and are functional with synthetic data
- [ ] WebSocket connection for real-time alert streaming
- [ ] Dashboard renders correctly on 1440px wide screen (primary target)
- [ ] No default Tailwind colors used directly — custom token system
      with at least: bg-void (near-black), bg-surface (dark card),
      text-signal (primary white), text-muted, accent-threat (red),
      accent-phantom (amber), accent-safe (green), accent-drift (blue)
- [ ] No lorem ipsum anywhere — all copy references actual system behavior
- [ ] Loading states handled for all async data
- [ ] Empty state for alert queue: "No alerts in current window"

---

## AXIS 8 — Code Quality & Security

Checklist for 100:

- [ ] Python: type hints on all function signatures
- [ ] Python: no bare `except` clauses — all exceptions caught and logged
      with `logging` module (not print)
- [ ] FastAPI: Pydantic models for all request and response bodies
- [ ] FastAPI: input validation before any ML inference is called
- [ ] React: TypeScript strict mode, zero `any` types
- [ ] React: no `console.log` in production paths
- [ ] No API keys hardcoded anywhere — all via `.env` + `python-dotenv`
- [ ] `requirements.txt` and `package.json` both present and complete
- [ ] `README.md` documents: setup, how to run the generator, how to start
      the server and dashboard, how to replay a demo scenario

---

## PROJECT STRUCTURE

```
phantom-twin/
├── backend/
│   ├── data/
│   │   ├── generator.py          # Synthetic data generator
│   │   ├── profiles/             # Per-entity JSON profiles (generated)
│   │   ├── train.csv             # Generated training set
│   │   ├── test.csv              # Generated test set (no labels)
│   │   └── labels_test.csv       # Held-out labels for evaluation
│   ├── models/
│   │   ├── profiler.py           # Builds + serializes entity profiles
│   │   ├── detector.py           # Isolation Forest + z-score scorer
│   │   ├── classifier.py         # Rule-based attack type classifier
│   │   ├── explainer.py          # Natural language explanation generator
│   │   └── phantom.py            # Phantom Twin decoy session generator
│   ├── pipeline.py               # Chains all models end-to-end
│   ├── evaluate.py               # Precision/recall/AUC evaluation
│   ├── main.py                   # FastAPI app + WebSocket endpoint
│   ├── schemas.py                # Pydantic models for all I/O
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── AlertQueue.tsx     # Left pane alert list
│   │   │   ├── AlertCard.tsx      # Individual alert with expand
│   │   │   ├── PhantomPane.tsx    # Right pane phantom session
│   │   │   ├── EntityHistory.tsx  # Entity timeline modal
│   │   │   ├── SystemHeader.tsx   # Live counters + health badge
│   │   │   └── FilterBar.tsx      # Alert filter controls
│   │   ├── hooks/
│   │   │   ├── useAlertStream.ts  # WebSocket hook for live alerts
│   │   │   └── usePhantom.ts      # Phantom session state
│   │   ├── types/
│   │   │   └── PhantomTwin.ts     # All TypeScript interfaces
│   │   ├── constants.ts           # Color tokens, thresholds, labels
│   │   └── App.tsx
│   ├── package.json
│   └── tailwind.config.js
├── report/
│   └── PHANTOM_TWIN_REPORT.md    # Assumptions, metrics, limitations
└── README.md
```

---

## CUSTOM COLOR TOKENS (tailwind.config.js)

```js
colors: {
  void:    '#0A0B0E',   // page background
  surface: '#111318',   // card background
  border:  '#1E2028',   // card borders
  signal:  '#F0F2F5',   // primary text
  muted:   '#6B7280',   // secondary text
  phantom: '#F59E0B',   // amber — phantom active state
  threat:  '#EF4444',   // red — critical/high alerts
  warn:    '#F97316',   // orange — medium alerts
  drift:   '#3B82F6',   // blue — profile shift / insider drift
  safe:    '#22C55E',   // green — normal / resolved
}
```

---

## DEMO SCENARIO (for judges)

The demo runs a pre-scripted replay of the synthetic test set, surface-level
real-time. Run `python backend/demo_replay.py` to stream events through the
pipeline at 5x speed. The dashboard should show:

1. Normal baseline events flowing in (LOW score, gray badges)
2. A brute force attack fires (CRITICAL, red badge, PHANTOM TWIN activates)
3. Phantom pane shows attacker probing fake resources for 30 seconds
4. An impossible travel event fires on a different entity (HIGH, orange)
5. A low-and-slow exfiltration pattern surfaces after 60 seconds of
   gradual events (MEDIUM, yellow, with timeline showing buildup)
6. Analyst closes phantom session — summary card appears
7. A cold-start entity triggers (bootstrap profile badge visible)

Demo should run in under 3 minutes and show every major feature.

---

## REPORT STRUCTURE (report/PHANTOM_TWIN_REPORT.md)

1. **System Overview** — architecture diagram (ASCII), how the 5 components
   chain together, where Phantom Twin fits
2. **Data Generation Assumptions** — per-attack-pattern behavioral logic,
   injection rates, class distribution table
3. **Model Choices & Rationale** — why Isolation Forest over LSTM (speed,
   explainability, cold-start friendliness), why rule-based classifier
   over learned classifier (interpretable, auditable, fewer FP)
4. **Evaluation Metrics** — precision, recall, F1 per class, AUC-ROC,
   FPR at top-1% threshold, confusion matrix
5. **Honeywell OT/ICS Applicability** — how this maps to edge gateway
   and ICS device protection (the Phantom Twin for PLCs angle)
6. **Known Limitations** — LSTM/Transformer would improve sequence modeling,
   rule-based classifier fails on novel attack variants, phantom session
   is simulated not networked
7. **Scalability Design** — how to move from batch to Kafka stream,
   how profiles scale horizontally with Redis

---

## STOPPING CONDITION

You are done when:

1. `python backend/data/generator.py` produces train.csv and test.csv
2. `python backend/pipeline.py --event <sample_event.json>` returns a
   full alert dict with risk_score, attack_type, explanation, and
   phantom_session fields
3. `python backend/evaluate.py` prints per-class metrics without error
4. `cd frontend && npm run dev` launches the dashboard and connects
   to the WebSocket
5. The demo replay runs end-to-end and all 7 demo scenario steps are
   visible in the dashboard
6. Self-evaluation scores are filled in honestly
7. README documents how to reproduce every step above

Do not declare done if any step above fails or is simulated with
placeholder data. Placeholder UI is acceptable only if labeled
"[DEMO MODE — replace with live data]" and documented in the report.

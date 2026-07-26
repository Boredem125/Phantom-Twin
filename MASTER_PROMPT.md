# PHANTOM TWIN — Master Build Prompt
# Paste this entire prompt to start the build session.
# Do not modify the system sections. Fill in the [FILL] placeholders only.

---

## CONTEXT

You are building **PHANTOM TWIN** — a hackathon submission for Honeywell's
behavioral anomaly detection challenge. Read SKILL.md before writing a
single line of code. Everything in that file is your specification.

The system detects compromised-credential and intrusion activity in
access logs, classifies the attack type, explains every alert in
human-readable English, and — the core differentiator — activates a
live Phantom Twin decoy session when a high-confidence anomaly fires,
trapping the attacker in a synthetic environment built from their victim's
own behavioral profile while the SOC alert fires silently.

---

## WHAT HONEYWELL IS EVALUATING

1. Detection accuracy on imbalanced labels
2. Correct anomaly-type classification (7 attack types)
3. False positive rate at top 1% of events (analyst alert budget)
4. Explainability — why did this alert fire, not just a score
5. Cold-start handling — new entity with no history
6. Concept drift — legitimate behavioral change vs. real anomaly
7. System design and real-time streaming feasibility
8. Report clarity

PHANTOM TWIN addresses all 8. Phantom Twin is the angle that wins.
Do not drop it to save time.

---

## BUILD ORDER

Do not skip steps. Do not reorder. Build each piece, verify it works,
then move to the next.

### STEP 1 — Synthetic Data Generator

File: `backend/data/generator.py`

Build a Python script that generates behavioral access logs according
to the schema below. It must accept `--n_entities`, `--n_events`,
and `--seed` as CLI args. It must output `train.csv`, `test.csv`,
and `labels_test.csv` (labels held out for evaluation only).

Schema:
```
entity_id, entity_type, timestamp, source_ip, geo_location,
resource_accessed, auth_method, session_duration, command_sequence,
device_fingerprint, label
```

Entity types: user (50%), service_account (25%), edge_device (25%)
Attack injection rate: 0.5–3% of total events
Label values: normal, brute_force, impossible_travel,
credential_stuffing, lateral_movement, device_spoofing,
low_and_slow, insider_drift

Per-entity normal profile:
- Login hours: sample from Gaussian(mu=entity_peak_hour, sigma=1.5)
- Geo: weighted random from entity's home geo set (2–4 locations)
- Resource access: Markov chain over entity's typical resource set
- Auth method: entity's preferred method (90% consistent)
- Device fingerprint: 1–3 known fingerprints per entity
- Session duration: Gaussian(mu=entity_avg_duration, sigma=5min)

Attack simulation rules (implement exactly):
- brute_force: 5–20 failed auth attempts within 60 seconds, same source_ip
- impossible_travel: two logins from geo > 2000km apart within 90 minutes
- credential_stuffing: 10–50 entity_ids, 1–2 source_ips, failure_rate > 0.7
- lateral_movement: access to 5+ resources never in entity's normal set,
  within a single session
- device_spoofing: login with device_fingerprint not in entity's known set
- low_and_slow: 1–3 small off-hours resource accesses per day, building
  over 3–7 days before becoming detectable
- insider_drift: gradual expansion of resource footprint over 7–14 days,
  always within business hours, no auth failures

After writing the generator, run it with:
```bash
python backend/data/generator.py --n_entities 200 --n_events 50000 --seed 42
```
Verify: train.csv has ~47,000 rows, test.csv has ~3,000 rows,
anomaly rate in labels_test.csv is between 0.5% and 3%.

---

### STEP 2 — Behavioral Profiler

File: `backend/models/profiler.py`

Build entity behavioral profiles from train.csv. For each entity_id:
- Compute login hour distribution (mean, std)
- Build weighted geo set
- Build resource access frequency map
- Compute session duration (mean, std)
- Collect known device fingerprints (set)
- Record most common auth method

Serialize each profile to `backend/data/profiles/<entity_id>.json`.

Cold-start logic: when scoring an entity with no profile, find the 5
most similar entities by entity_type from existing profiles, average
their distributions. Set profile.bootstrap = true.

Run:
```bash
python backend/models/profiler.py --input backend/data/train.csv
```
Verify: profiles/ directory contains one JSON per entity_id.

---

### STEP 3 — Anomaly Detector

File: `backend/models/detector.py`

Input: a single event dict + the entity's profile
Output: risk_score (0–100) + feature_deviations dict

Compute per-feature z-scores:
- hour_deviation: how many sigma from entity's normal login hour
- geo_deviation: 0 if known geo, 1 if new geo, geo_distance_score if far
- resource_novelty: fraction of accessed resources not in entity's top-20
- session_duration_z: sigma from entity's normal session duration
- auth_method_change: 0 if normal method, 1 if changed
- fingerprint_mismatch: 0 if known fingerprint, 1 if unknown

Train a shared Isolation Forest on the z-score feature vectors from
train.csv. Save model to `backend/models/iso_forest.pkl`.

Risk score = 0.4 * isolation_score + 0.6 * weighted_z_score_composite
Normalize to 0–100.

Thresholds: LOW < 40, MEDIUM 40–70, HIGH 70–85, CRITICAL > 85

---

### STEP 4 — Anomaly Classifier

File: `backend/models/classifier.py`

Input: event dict + feature_deviations dict
Output: attack_type (string) + confidence (0.0–1.0)

Implement rule-based classification (ordered, first match wins unless
multi-label explicitly possible):

```python
def classify(event, deviations, recent_events_for_entity):
    if count_failed_auth_in_window(recent_events, window_seconds=60) >= 5:
        return "brute_force", confidence_from_count(n_failed)

    if impossible_travel_check(event, recent_events):
        # geo distance / time gap implies speed > 900 km/h
        return "impossible_travel", confidence_from_speed(implied_speed)

    if credential_stuffing_check(recent_events_all_entities):
        # many entity_ids, few source_ips, high failure rate
        return "credential_stuffing", 0.85

    if deviations["fingerprint_mismatch"] == 1:
        return "device_spoofing", 0.9

    if deviations["resource_novelty"] > 0.8 and resource_breadth_3x_baseline:
        return "lateral_movement", confidence_from_novelty(novelty_score)

    if low_and_slow_accumulation_check(recent_events):
        # small off-hours accesses building over days
        return "low_and_slow", 0.75

    if insider_drift_check(entity_profile_history):
        # gradual resource expansion over 7+ days, no failures
        return "insider_drift", 0.6

    return "normal", 1.0 - (risk_score / 100)
```

Confidence is calibrated: brute force with 20 failures should be 0.99.
Insider drift is inherently uncertain, cap at 0.7.

---

### STEP 5 — Explainer

File: `backend/models/explainer.py`

Input: classified event + feature_deviations + profile
Output: explanation_text (string) + feature_attribution (dict)

Template for explanation_text:
```
"{entity_id} ({entity_type}) accessed {resource_accessed} at {timestamp}.
Risk factors: {top_3_deviations_in_plain_english}.
Attack pattern: {attack_type} ({confidence_pct}% confidence).
{attack_specific_detail}"
```

Attack-specific detail templates:
- impossible_travel: "Origin: {geo_a} → {geo_b}, {distance_km}km in {minutes}min ({speed_kmh} km/h implied)"
- brute_force: "{n_failures} failed auth attempts in {window_seconds}s from {source_ip}"
- device_spoofing: "Known fingerprints: {known_fps}. Observed: {observed_fp}"
- lateral_movement: "{n_novel} resources accessed outside normal set of {n_normal} resources"
- low_and_slow: "Pattern detected over {n_days} days, {total_bytes_or_events} cumulative"

Feature attribution dict:
```json
{
  "hour_deviation": { "baseline": 9.2, "observed": 3.1, "delta": -6.1, "weight": 0.2 },
  "geo_deviation":  { "baseline": "Mumbai", "observed": "Berlin", "delta": "new_geo", "weight": 0.3 },
  ...
}
```

---

### STEP 6 — Phantom Twin

File: `backend/models/phantom.py`

Input: entity profile + attacker's current session context
Output: PhantomSession object with methods:

```python
class PhantomSession:
    entity_id: str
    activated_at: datetime
    source_ip: str           # real attacker's IP
    actions: list[PhantomAction]
    status: "ACTIVE" | "TERMINATED"
    
    def respond_to_auth(self) -> dict:
        # returns fake success response
        return { "status": "authenticated", "token": fake_token(), "session_id": uuid4() }
    
    def respond_to_resource_probe(self, resource: str) -> dict:
        # returns fake resource listing sampled from entity's profile
        return { "status": "ok", "contents": sample_fake_resources(self.profile) }
    
    def log_action(self, action_type: str, details: dict):
        self.actions.append(PhantomAction(
            timestamp=now(), action_type=action_type, details=details
        ))
    
    def terminate(self) -> PhantomSummary:
        return PhantomSummary(
            duration_seconds=...,
            n_actions=len(self.actions),
            action_types=Counter([a.action_type for a in self.actions]),
            resources_probed=list(set(a.details.get("resource") for a in self.actions))
        )
```

PhantomSession is stored in memory (dict keyed by entity_id) during
the demo. It does not persist between server restarts — this is fine
for the hackathon scope.

---

### STEP 7 — Pipeline

File: `backend/pipeline.py`

Chains all 5 models end-to-end. Input: raw event dict. Output:
enriched alert dict.

```python
def process_event(event: dict) -> dict:
    profile = load_profile(event["entity_id"])  # or bootstrap if new
    deviations = detector.score(event, profile)
    attack_type, confidence = classifier.classify(event, deviations, recent_events)
    explanation = explainer.explain(event, deviations, profile, attack_type, confidence)
    
    alert = {
        "event": event,
        "risk_score": deviations["risk_score"],
        "risk_level": risk_level(deviations["risk_score"]),
        "attack_type": attack_type,
        "confidence": confidence,
        "explanation": explanation["text"],
        "feature_attribution": explanation["attribution"],
        "profile_bootstrap": profile.get("bootstrap", False),
        "phantom_session": None
    }
    
    if alert["risk_level"] in ("HIGH", "CRITICAL"):
        session = phantom.activate(event["entity_id"], profile, event["source_ip"])
        alert["phantom_session"] = session.to_dict()
    
    return alert
```

Test it manually:
```bash
python backend/pipeline.py --event backend/data/sample_events/brute_force.json
```
Expected output: risk_score > 85, attack_type = "brute_force",
phantom_session not null.

---

### STEP 8 — FastAPI Backend

File: `backend/main.py`

Endpoints:

```
POST /api/event           # process a single event, return alert dict
GET  /api/alerts          # return last N alerts (default 50)
GET  /api/entity/{id}     # return entity profile + last 100 events
GET  /api/phantom/{id}    # return active phantom session for entity
POST /api/phantom/{id}/terminate  # terminate phantom session
WS   /ws/alerts           # WebSocket: streams alerts in real time
```

Pydantic models for all request/response bodies in `backend/schemas.py`.
Validation before any ML inference. Return HTTP 422 with field name on
invalid input, never 500 on bad input.

Also build `backend/demo_replay.py`:
- Reads test.csv row by row
- Calls pipeline.process_event() with configurable delay (default 0.2s)
- Pushes result to the WebSocket broadcast channel
- Prints progress: "Event 1000/3000 | Alerts fired: 42 | Active phantoms: 2"

---

### STEP 9 — Frontend Dashboard

Stack: React 18, TypeScript strict, Tailwind CSS, shadcn/ui.
No chart libraries except Recharts for timeline sparklines only.

Color tokens (add to tailwind.config.js):
```js
void:    '#0A0B0E',
surface: '#111318',
border:  '#1E2028',
signal:  '#F0F2F5',
muted:   '#6B7280',
phantom: '#F59E0B',
threat:  '#EF4444',
warn:    '#F97316',
drift:   '#3B82F6',
safe:    '#22C55E',
```

Typography: use `font-mono` for all data values, entity IDs, IPs,
timestamps, scores. Use a clean sans-serif (Inter or system-ui) for
labels and explanations. This mirrors CITADEL's command-center feel.

Layout: full-width two-pane. Left pane 60% (alert queue). Right pane
40% (phantom session OR entity history when selected). Header bar spans
full width with system counters.

Build order within frontend:
1. `SystemHeader.tsx` — live counters, health badge, PHANTOM TWIN wordmark
2. `AlertCard.tsx` — single alert with expand/collapse, all data fields
3. `AlertQueue.tsx` — scrollable list of AlertCards, filter bar on top
4. `PhantomPane.tsx` — live phantom session view with action feed
5. `EntityHistory.tsx` — modal with entity timeline
6. `useAlertStream.ts` — WebSocket hook that reconnects on drop
7. `App.tsx` — assembles layout, manages selected alert state

Design notes from CITADEL reference:
- The wordmark in the header should be bold, monospaced, all-caps:
  "PHANTOM TWIN" with a subtle amber pulse on the dot/icon
- Alert cards have a left border that changes color by risk level
  (red for CRITICAL, orange for HIGH, yellow for MEDIUM, gray for LOW)
- PHANTOM ACTIVE badge should pulse — use CSS keyframe animation,
  not a library
- Entity IDs, IPs, and fingerprints render in monospace amber on dark
  surface — this is the visual identity, lean into it
- Risk score renders as a large number (bold, 2rem) with a small label
  underneath: "RISK SCORE"
- The phantom pane header: dark background, "PHANTOM SESSION ACTIVE"
  in amber caps, elapsed timer counting up

---

### STEP 10 — Evaluate and Report

Run evaluation:
```bash
python backend/evaluate.py \
  --test backend/data/test.csv \
  --labels backend/data/labels_test.csv
```
Output: per-class precision, recall, F1 + confusion matrix + AUC-ROC +
FPR at top-1% events threshold.

Write `report/PHANTOM_TWIN_REPORT.md` covering:
1. System architecture (ASCII diagram of pipeline)
2. Data generation assumptions per attack pattern
3. Model choices and why (Isolation Forest, rule-based classifier)
4. Evaluation results table (paste from evaluate.py output)
5. Phantom Twin design rationale and Honeywell OT/ICS applicability
6. Known limitations (honest — judges respect this)
7. Scaling path (Kafka for streaming, Redis for profile store)

---

## SELF-EVALUATION (fill in after Step 10)

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
  - [list honestly]

What was NOT implemented and why:
  - [list scope cuts with reason]
```

---

## CONSTRAINTS

- Do not spend time on Docker or CI/CD setup — not evaluated
- Do not implement real network-level honeypotting — simulation is enough
  and clearly scoped for the demo
- Do not use Streamlit for the dashboard — judges will notice and it
  reads as low-effort
- Do not add features not in this spec without finishing what is here first
- If you run out of time, cut in this order (least impact first):
  1. Entity history modal (keep the data, skip the modal)
  2. Profile shift events on timeline
  3. Demo replay speed configurability (hardcode 0.2s)
  Keep: Phantom Twin, Alert Queue, Explainability, Classification. These
  are the axes that differentiate the submission.

---

## SUCCESS LOOKS LIKE

A judge opens the demo. Within 90 seconds they see:
- A stream of events flowing in with scores
- A CRITICAL alert fire with a clear, specific explanation
- "PHANTOM SESSION ACTIVE" appear in amber in the right pane
- The attacker's actions inside the decoy populating in real time
- The analyst clicking "Terminate" and seeing the summary card

That is the moment that wins. Build toward it.

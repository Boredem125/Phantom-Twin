import pandas as pd
from collections import deque
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.models.profiler import load_profile
from backend.models.detector import score_event
from backend.models.classifier import classify

df_test = pd.read_csv("backend/data/test.csv")
df_labels = pd.read_csv("backend/data/labels_test.csv")
df_merged = df_test.merge(df_labels, on=["entity_id", "timestamp"], how="left").fillna("normal")

cs_events = df_merged[df_merged["label"] == "credential_stuffing"]
print("Total credential stuffing events in test set:", len(cs_events))

# Replay all events up to the credential stuffing events
entity_recent = {}
global_recent = deque(maxlen=1000)

for i, row in df_merged.iterrows():
    event = row.to_dict()
    true_label = event.pop("label")
    entity_id = event["entity_id"]
    
    if entity_id not in entity_recent:
        entity_recent[entity_id] = deque(maxlen=500)
        
    entity_recent[entity_id].append(event)
    global_recent.append(event)
    
    if true_label == "credential_stuffing":
        profile = load_profile(entity_id, event["entity_type"])
        score_result = score_event(event, profile, None)
        deviations = score_result["feature_deviations"]
        
        # Run credential stuffing check directly
        from backend.models.classifier import _credential_stuffing_check
        is_cs, n_ents, n_ips, failure_rate = _credential_stuffing_check(event, list(global_recent))
        
        # Run full classify
        attack_type, conf, meta = classify(
            event=event,
            deviations=deviations,
            recent_events=list(entity_recent[entity_id]),
            recent_all_events=list(global_recent),
            profile=profile,
            risk_score=score_result["risk_score"]
        )
        
        print(f"Event at {event['timestamp']} for {entity_id}:")
        print(f"  CS check: is_cs={is_cs}, n_ents={n_ents}, n_ips={n_ips}, fail_rate={failure_rate}")
        print(f"  Classified as: {attack_type} (conf={conf})")

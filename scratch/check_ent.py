import pandas as pd
df_test = pd.read_csv("backend/data/test.csv")
df_labels = pd.read_csv("backend/data/labels_test.csv")
df_merged = df_test.merge(df_labels, on=["entity_id", "timestamp"], how="left").fillna("normal")

ent_events = df_merged[df_merged["entity_id"] == "ENT-0187"].sort_values("timestamp")
print(ent_events[["timestamp", "resource_accessed", "source_ip", "label"]])

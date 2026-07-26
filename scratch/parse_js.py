import json

transcript_path = r"C:\Users\Dell\.gemini\antigravity\brain\05441d76-c7cf-423a-a227-bd5933f9d2e4\.system_generated\logs\transcript.jsonl"

with open(transcript_path, "r", encoding="utf-8") as f:
    for line in f:
        try:
            obj = json.loads(line)
            if "content" in obj and "skeleton" in obj["content"].lower():
                print(f"Step {obj.get('step_index')} content mention of skeleton:")
                print(obj["content"][:300])
        except Exception as e:
            pass

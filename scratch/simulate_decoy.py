import time
import httpx

API_BASE = "http://localhost:8000"
ENTITY_ID = "ENT-0099"

def run_simulation():
    client = httpx.Client()
    
    # 1. Trigger the CRITICAL anomaly
    print("Step 1: Sending anomalous event to trigger CRITICAL alert and activate decoy...")
    event_payload = {
        "entity_id": ENTITY_ID,
        "entity_type": "user",
        "timestamp": "2025-03-24T12:00:00",
        "source_ip": "198.51.100.42",
        "geo_location": "Moscow",
        "resource_accessed": "/api/v1/admin/secrets",
        "auth_method": "password",
        "session_duration": 150.0,
        "command_sequence": "sudo,nmap,hydra",
        "device_fingerprint": "unknown-device-fingerprint-999"
    }
    
    try:
        resp = client.post(f"{API_BASE}/api/event", json=event_payload, timeout=10.0)
        if resp.status_code == 200:
            alert = resp.json()
            print(f"-> Alert generated: {alert['alert_id']} | Risk Level: {alert['risk_level']} | Phantom Activated: {alert['phantom_activated']}")
        else:
            print(f"-> API Error: {resp.status_code} - {resp.text}")
            return
    except Exception as e:
        print("-> Connection failed:", e)
        return
        
    # 2. Stream attacker actions into the decoy session
    actions = [
        ("AUTH_ATTEMPT", {"username": "admin", "password": "honeywell_admin_123", "result": "fake_success"}),
        ("RESOURCE_PROBE", {"resource": "/decoy/api/v1/secrets/master-key", "result": "fake_ok", "items": 1}),
        ("PRIVILEGE_ESCALATION_ATTEMPT", {"target_role": "superadmin", "escalation_vector": "sudo_exploit", "result": "fake_granted"}),
        ("LATERAL_PROBE", {"target_subnet": "10.0.2.0/24", "discovered_hosts": ["10.0.2.14", "10.0.2.15"]}),
        ("DATA_READ_ATTEMPT", {"resource": "/decoy/assets/credentials.json", "bytes_read": 4096, "content_preview": "{\"db_user\": \"admin\", \"db_pass\": \"honeywell123\"}"})
    ]
    
    print("\nStep 2: Simulating attacker commands inside the decoy containment. Check dashboard right pane!")
    for action_type, details in actions:
        time.sleep(2.5)
        action_payload = {
            "entity_id": ENTITY_ID,
            "action_type": action_type,
            "details": details
        }
        try:
            resp = client.post(f"{API_BASE}/api/phantom/{ENTITY_ID}/action", json=action_payload)
            if resp.status_code == 200:
                print(f"-> Trapped attacker action logged: {action_type}")
            else:
                print(f"-> Action logging failed: {resp.status_code} - {resp.text}")
        except Exception as e:
            print("-> Action post error:", e)

    print("\nSimulation complete. The decoy session remains active. You can manual-terminate it in the UI.")

if __name__ == "__main__":
    run_simulation()

import sys
sys.path.insert(0, '.')

from backend.tools.synthetic_generator import _normal_event, _brute_force_event, _lateral_event, _make_foreign_ip, _impossible_travel_pair, _spoofing_event
from backend.pipeline import process_event

tests = [
    ("NORMAL",    _normal_event('ENT-0010')),
    ("BRUTEFORCE", _brute_force_event('ENT-0010', _make_foreign_ip())),
    ("LATERAL",   _lateral_event('ENT-0010')),
    ("SPOOFING",  _spoofing_event('ENT-0010')),
    ("TRAVEL_2",  _impossible_travel_pair('ENT-0010')[1]),
]

for label, ev in tests:
    r = process_event(ev)
    print(f"{label:12s} -> risk={r['risk_score']:5.1f}  level={r['risk_level']:8s}  attack={r['attack_type']}")

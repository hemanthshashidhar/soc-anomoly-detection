from alerts.alert_engine import AlertEngine
from intelligence.narrative_engine import AttackNarrativeEngine
from realtime_event_builder import build_event

alert_engine = AlertEngine()
narrative_engine = AttackNarrativeEngine()

def analyze_realtime_event(user, ip):
    event = build_event(user, ip)

    alert = alert_engine.process_event(event)
    alert["attack_type"] = narrative_engine.classify_attack(alert)
    alert["narrative"] = narrative_engine.build_narrative(alert)

    return alert

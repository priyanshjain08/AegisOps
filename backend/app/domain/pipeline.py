"""Framework-free orchestration used by the service layer and tests:
records -> normalized events -> findings -> alert refs -> incident groups."""
from __future__ import annotations
import uuid
from .events import normalize_batch
from .detection import default_rules, run_rules, Rule
from .correlation import AlertRef, correlate
from .severity import score_alert, band

def process(records, rules: list[Rule] | None = None, window_minutes: int = 60, source_type="generic"):
    events, errors = normalize_batch(records, source_type)
    for e in events:
        e.attributes.setdefault("_id", str(uuid.uuid4()))
    findings = run_rules(rules or default_rules(), events)
    alerts = []
    for f in findings:
        score = score_alert(f.severity, None, f.confidence)
        alerts.append({"id": str(uuid.uuid4()), "finding": f, "score": score, "severity": band(score),
                       "event_ids": [e.attributes["_id"] for e in f.events]})
    refs = [AlertRef(a["id"], a["finding"].category, a["severity"], min(e.timestamp for e in a["finding"].events),
                     a["finding"].entities) for a in alerts]
    groups = correlate(refs, window_minutes)
    return {"events": events, "errors": errors, "alerts": alerts, "incidents": groups}

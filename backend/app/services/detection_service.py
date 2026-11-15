"""Bridges DB <-> pure domain engine. Used for new ingests and historical re-evaluation."""
import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.models import DetectionRule, DetectionRuleExecution, SecurityEvent, Alert, Incident, IncidentAlert, IncidentEvent, Asset
from app.domain.detection import default_rules, Rule, run_rules
from app.domain.events import NormalizedEvent
from app.domain.correlation import AlertRef, correlate
from app.domain.severity import score_alert, band

def ensure_default_rules(db: Session, org_id):
    have = {r.rule_key for r in db.query(DetectionRule).filter_by(organization_id=org_id)}
    for r in default_rules():
        if r.id not in have:
            db.add(DetectionRule(organization_id=org_id, rule_key=r.id, name=r.name, description=r.description,
                                 category=r.category, severity=r.severity, thresholds=r.thresholds))
    db.flush()

def _to_domain(e: SecurityEvent) -> NormalizedEvent:
    n = NormalizedEvent(e.timestamp, e.source_type, e.category, e.action, e.hostname, e.username, e.source_ip,
                        e.destination_ip, e.severity, e.result, e.raw, dict(e.attributes or {}), e.dedup_hash)
    n.attributes["_id"] = str(e.id)
    return n

def evaluate(db: Session, org_id, since: datetime | None = None, window_minutes: int = 60) -> dict:
    ensure_default_rules(db, org_id)
    q = db.query(SecurityEvent).filter_by(organization_id=org_id)
    if since:
        q = q.filter(SecurityEvent.timestamp >= since)
    rows = q.order_by(SecurityEvent.timestamp).all()
    events = [_to_domain(e) for e in rows]
    db_rules = {r.rule_key: r for r in db.query(DetectionRule).filter_by(organization_id=org_id)}
    base = {r.id: r for r in default_rules()}
    rules = []
    for k, dbr in db_rules.items():
        if k in base:
            r = base[k]; r.enabled, r.thresholds, r.version = dbr.enabled, dbr.thresholds, dbr.version
            rules.append(r)
    findings = run_rules(rules, events)
    existing = {(a.rule_id, tuple(sorted(a.event_ids))) for a in db.query(Alert).filter_by(organization_id=org_id)}
    created = []
    for f in findings:
        eids = sorted(e.attributes["_id"] for e in f.events)
        dbr = db_rules[f.rule_id]
        if (dbr.id, tuple(eids)) in existing:
            continue  # same rule + same evidence => same alert; evaluation is idempotent
        host = f.entities.get("hostname") or next((e.hostname for e in f.events if e.hostname), None)
        asset = db.query(Asset).filter_by(organization_id=org_id, hostname=host).first() if host else None
        score = score_alert(f.severity, asset.criticality if asset else None, f.confidence)
        a = Alert(organization_id=org_id, rule_id=dbr.id, title=f.title, description=f.description, severity=band(score),
                  score=score, category=f.category, confidence=f.confidence, entities=f.entities, event_ids=eids,
                  is_simulated=any(e.raw.get("simulated") for e in f.events))
        db.add(a); created.append(a)
    for dbr in db_rules.values():
        dbr.last_executed_at = datetime.now(timezone.utc)
        db.add(DetectionRuleExecution(organization_id=org_id, rule_id=dbr.id, events_evaluated=len(events)))
    db.flush()
    _correlate(db, org_id, created, window_minutes)
    return {"events_evaluated": len(events), "alerts_created": len(created)}

def _correlate(db: Session, org_id, new_alerts, window_minutes):
    if not new_alerts:
        return
    pool = db.query(Alert).filter(Alert.organization_id == org_id, Alert.status != "false_positive",
            Alert.created_at >= datetime.now(timezone.utc) - timedelta(days=7)).all()
    ts_of = lambda a: min(e.timestamp for e in db.query(SecurityEvent).filter(SecurityEvent.id.in_([uuid.UUID(i) for i in a.event_ids])))
    refs = [AlertRef(str(a.id), a.category, a.severity, ts_of(a), a.entities) for a in pool if a.event_ids]
    by_id = {str(a.id): a for a in pool}
    order = ["informational", "low", "medium", "high", "critical"]
    for g in correlate(refs, window_minutes):
        members = [by_id[i] for i in g.alert_ids]
        if not any(m in new_alerts for m in members):
            continue
        inc_ids = {m.incident_id for m in members if m.incident_id}
        inc = db.get(Incident, next(iter(inc_ids))) if inc_ids else None
        sev = max((m.severity for m in members), key=order.index)
        if inc is None:
            inc = Incident(organization_id=org_id, title=members[0].title if len(members) == 1 else f"{members[0].title} (+{len(members)-1} related)",
                           description="Auto-correlated from shared entities: " + ", ".join(f"{k}={v}" for k, v in sorted(g.shared)) if g.shared else "Auto-correlated.",
                           severity=sev, is_simulated=any(m.is_simulated for m in members))
            db.add(inc); db.flush()
        inc.severity = max(sev, inc.severity, key=order.index)
        for m in members:
            if m.incident_id is None:
                m.incident_id = inc.id
                db.add(IncidentAlert(incident_id=inc.id, alert_id=m.id))
                for eid in m.event_ids:
                    if not db.get(IncidentEvent, (inc.id, uuid.UUID(eid))):
                        db.add(IncidentEvent(incident_id=inc.id, event_id=uuid.UUID(eid)))
    db.flush()

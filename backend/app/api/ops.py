"""Events, ingestion, alerts, assets, rules, dashboard, audit. Every query is scoped by ctx.org_id."""
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from sqlalchemy import func, or_
from sqlalchemy.orm import Session
from app.core.db import get_db
from app.core.config import settings
from app.core.deps import Ctx, current_ctx, require
from app.models import *
from app.audit import audit
from app.services import ingest_service as ing, detection_service as det
from app.domain.scenarios import SCENARIOS, generate
from .schemas import AssetIn, AlertPatch, RulePatch

router = APIRouter(prefix="/api")

def _uuid(v: str):
    try: return uuid.UUID(v)
    except ValueError: raise HTTPException(422, "Invalid identifier")

def _get(db, model, id_, ctx):
    obj = db.query(model).filter_by(id=_uuid(id_), organization_id=ctx.org_id).first()
    if not obj: raise HTTPException(404, "Not found")  # same response for other-org ids: no existence leak
    return obj

def row(o, *skip):
    return {c.name: (str(getattr(o, c.name)) if isinstance(getattr(o, c.name), uuid.UUID) else getattr(o, c.name))
            for c in o.__table__.columns if c.name not in skip}

def page(q, p, size):
    total = q.count(); return {"total": total, "page": p, "page_size": size, "items": q.offset((p - 1) * size).limit(size).all()}

# ---- Ingestion
@router.post("/ingestion/upload", status_code=202)
async def upload(file: UploadFile = File(...), fmt: str = Query(..., pattern="^(json|jsonl|csv)$"), source_type: str = "generic",
                 db: Session = Depends(get_db), ctx: Ctx = Depends(require("analyst"))):
    data = await file.read()
    if len(data) > settings.max_upload_mb * 1024 * 1024: raise HTTPException(413, "File too large")
    try: records = ing.parse_payload(fmt, data)
    except Exception as e: raise HTTPException(422, f"Could not parse {fmt}: {e}")
    job = IngestionJob(organization_id=ctx.org_id, filename=file.filename, fmt=fmt); db.add(job); db.flush()
    if len(records) > settings.sync_ingest_limit:
        from app.workers.tasks import ingest_task
        ingest_task.delay(str(ctx.org_id), str(job.id), records, source_type)   # async path for large uploads
    else:
        ing.ingest_records(db, ctx.org_id, job, records, source_type); det.evaluate(db, ctx.org_id)
    audit(db, ctx, "ingestion.upload", "ingestion_job", job.id, filename=file.filename, records=len(records)); db.commit()
    return row(job)

@router.post("/ingestion/events", status_code=202)
def api_ingest(body: dict, db: Session = Depends(get_db), ctx: Ctx = Depends(require("analyst"))):
    records = body.get("events")
    if not isinstance(records, list) or not records: raise HTTPException(422, "Body must be {\"events\": [ ... ]}")
    job = IngestionJob(organization_id=ctx.org_id, fmt="json", filename="api"); db.add(job); db.flush()
    ing.ingest_records(db, ctx.org_id, job, records, body.get("source_type", "generic")); det.evaluate(db, ctx.org_id)
    db.commit(); return row(job)

@router.get("/ingestion/jobs")
def jobs(p: int = 1, size: int = Query(25, le=100), db: Session = Depends(get_db), ctx: Ctx = Depends(current_ctx)):
    r = page(db.query(IngestionJob).filter_by(organization_id=ctx.org_id).order_by(IngestionJob.created_at.desc()), p, size)
    r["items"] = [row(j) for j in r["items"]]; return r

# ---- Events
@router.get("/events")
def events(p: int = 1, size: int = Query(50, le=200), q: str | None = None, severity: str | None = None, source_ip: str | None = None,
           hostname: str | None = None, username: str | None = None, category: str | None = None,
           start: datetime | None = None, end: datetime | None = None, db: Session = Depends(get_db), ctx: Ctx = Depends(current_ctx)):
    qry = db.query(SecurityEvent).filter_by(organization_id=ctx.org_id)
    for col, val in (("severity", severity), ("source_ip", source_ip), ("hostname", hostname), ("username", username), ("category", category)):
        if val: qry = qry.filter(getattr(SecurityEvent, col) == val)
    if start: qry = qry.filter(SecurityEvent.timestamp >= start)
    if end: qry = qry.filter(SecurityEvent.timestamp <= end)
    if q:
        like = f"%{q}%"; qry = qry.filter(or_(SecurityEvent.action.ilike(like), SecurityEvent.username.ilike(like), SecurityEvent.hostname.ilike(like), SecurityEvent.source_ip.ilike(like)))
    r = page(qry.order_by(SecurityEvent.timestamp.desc()), p, size); r["items"] = [row(e) for e in r["items"]]; return r

# ---- Alerts
@router.get("/alerts")
def alerts(p: int = 1, size: int = Query(25, le=100), severity: str | None = None, status: str | None = None, category: str | None = None,
           q: str | None = None, db: Session = Depends(get_db), ctx: Ctx = Depends(current_ctx)):
    qry = db.query(Alert).filter_by(organization_id=ctx.org_id)
    if severity: qry = qry.filter_by(severity=severity)
    if status: qry = qry.filter_by(status=status)
    if category: qry = qry.filter_by(category=category)
    if q: qry = qry.filter(Alert.title.ilike(f"%{q}%"))
    r = page(qry.order_by(Alert.created_at.desc()), p, size); r["items"] = [row(a) for a in r["items"]]; return r

@router.get("/alerts/{alert_id}")
def alert_detail(alert_id: str, db: Session = Depends(get_db), ctx: Ctx = Depends(current_ctx)):
    a = _get(db, Alert, alert_id, ctx)
    evs = db.query(SecurityEvent).filter(SecurityEvent.organization_id == ctx.org_id, SecurityEvent.id.in_([uuid.UUID(i) for i in a.event_ids])).order_by(SecurityEvent.timestamp).all()
    hist = db.query(AuditLog).filter_by(organization_id=ctx.org_id, resource_type="alert", resource_id=str(a.id)).order_by(AuditLog.created_at).all()
    return {**row(a), "events": [row(e) for e in evs], "history": [row(h) for h in hist]}

@router.patch("/alerts/{alert_id}")
def alert_patch(alert_id: str, body: AlertPatch, db: Session = Depends(get_db), ctx: Ctx = Depends(require("analyst"))):
    a = _get(db, Alert, alert_id, ctx); before = a.status
    if body.status: a.status = body.status
    if body.assigned_to:
        if not db.query(OrganizationMember).filter_by(organization_id=ctx.org_id, user_id=_uuid(body.assigned_to)).first():
            raise HTTPException(422, "Assignee is not a member of this organization")
        a.assigned_to = _uuid(body.assigned_to)
    audit(db, ctx, "alert.update", "alert", a.id, from_status=before, to_status=a.status, assigned_to=body.assigned_to); db.commit(); return row(a)

# ---- Assets
@router.get("/assets")
def assets(p: int = 1, size: int = Query(25, le=100), q: str | None = None, db: Session = Depends(get_db), ctx: Ctx = Depends(current_ctx)):
    qry = db.query(Asset).filter_by(organization_id=ctx.org_id)
    if q: qry = qry.filter(or_(Asset.name.ilike(f"%{q}%"), Asset.hostname.ilike(f"%{q}%"), Asset.ip_address.ilike(f"%{q}%")))
    r = page(qry.order_by(Asset.name), p, size); r["items"] = [row(a) for a in r["items"]]; return r

@router.post("/assets", status_code=201)
def asset_create(body: AssetIn, db: Session = Depends(get_db), ctx: Ctx = Depends(require("security_admin"))):
    a = Asset(organization_id=ctx.org_id, **body.model_dump()); db.add(a); db.flush(); audit(db, ctx, "asset.create", "asset", a.id); db.commit(); return row(a)

@router.put("/assets/{asset_id}")
def asset_update(asset_id: str, body: AssetIn, db: Session = Depends(get_db), ctx: Ctx = Depends(require("security_admin"))):
    a = _get(db, Asset, asset_id, ctx)
    for k, v in body.model_dump().items(): setattr(a, k, v)
    audit(db, ctx, "asset.update", "asset", a.id); db.commit(); return row(a)

@router.delete("/assets/{asset_id}", status_code=204)
def asset_delete(asset_id: str, db: Session = Depends(get_db), ctx: Ctx = Depends(require("security_admin"))):
    a = _get(db, Asset, asset_id, ctx); audit(db, ctx, "asset.delete", "asset", a.id, name=a.name); db.delete(a); db.commit()

@router.get("/assets/{asset_id}/risk")
def asset_risk(asset_id: str, db: Session = Depends(get_db), ctx: Ctx = Depends(current_ctx)):
    a = _get(db, Asset, asset_id, ctx)
    al = db.query(Alert).filter(Alert.organization_id == ctx.org_id, Alert.entities["hostname"].astext == a.hostname).all() if a.hostname else []
    open_ = [x for x in al if x.status in ("new", "acknowledged", "investigating")]
    return {"asset": row(a), "alerts_total": len(al), "alerts_open": len(open_), "max_open_score": max((x.score for x in open_), default=0),
            "note": "Risk is derived from alerts matched by hostname; this does not imply real-time monitoring."}

# ---- Detection rules
@router.get("/detection-rules")
def rules(db: Session = Depends(get_db), ctx: Ctx = Depends(current_ctx)):
    det.ensure_default_rules(db, ctx.org_id); db.commit()
    return [row(r) for r in db.query(DetectionRule).filter_by(organization_id=ctx.org_id).order_by(DetectionRule.rule_key)]

@router.patch("/detection-rules/{rule_id}")
def rule_patch(rule_id: str, body: RulePatch, db: Session = Depends(get_db), ctx: Ctx = Depends(require("security_admin"))):
    r = _get(db, DetectionRule, rule_id, ctx)
    if body.thresholds is not None:
        if set(body.thresholds) != set(r.thresholds): raise HTTPException(422, f"thresholds must have exactly keys {sorted(r.thresholds)}")
        r.thresholds, r.version = body.thresholds, r.version + 1
    if body.enabled is not None: r.enabled = body.enabled
    audit(db, ctx, "rule.update", "detection_rule", r.id, enabled=r.enabled, version=r.version); db.commit(); return row(r)

@router.post("/detection-rules/evaluate")
def rules_evaluate(db: Session = Depends(get_db), ctx: Ctx = Depends(require("security_admin"))):
    res = det.evaluate(db, ctx.org_id); audit(db, ctx, "rule.evaluate_historical", None, None, **res); db.commit(); return res

# ---- Dashboard (all numbers come from the DB)
@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db), ctx: Ctx = Depends(current_ctx)):
    o = ctx.org_id; c = lambda m, *f: db.query(func.count()).select_from(m).filter(m.organization_id == o, *f).scalar()
    grp = lambda col, m, *f: [{"key": k, "count": n} for k, n in db.query(col, func.count()).filter(m.organization_id == o, *f).group_by(col).order_by(func.count().desc()).limit(10)]
    over_time = [{"bucket": b.isoformat(), "count": n} for b, n in db.query(func.date_trunc("hour", SecurityEvent.timestamp), func.count()).filter(SecurityEvent.organization_id == o).group_by(1).order_by(1).limit(500)]
    return {"cards": {"total_events": c(SecurityEvent), "active_alerts": c(Alert, Alert.status.in_(["new", "acknowledged", "investigating"])),
                      "critical_alerts": c(Alert, Alert.severity == "critical", Alert.status.in_(["new", "acknowledged", "investigating"])),
                      "open_incidents": c(Incident, Incident.status.in_(["open", "investigating"])), "assets": c(Asset),
                      "pending_approvals": c(ResponseAction, ResponseAction.approval_status == "pending_approval")},
            "events_over_time": over_time, "alerts_by_severity": grp(Alert.severity, Alert), "incidents_by_status": grp(Incident.status, Incident),
            "detection_categories": grp(Alert.category, Alert), "top_source_ips": grp(SecurityEvent.source_ip, SecurityEvent, SecurityEvent.source_ip.isnot(None)),
            "recent_alerts": [row(a) for a in db.query(Alert).filter_by(organization_id=o).order_by(Alert.created_at.desc()).limit(8)],
            "recent_events": [row(e, "raw") for e in db.query(SecurityEvent).filter_by(organization_id=o).order_by(SecurityEvent.timestamp.desc()).limit(8)],
            "has_simulated_data": bool(c(SecurityEvent, SecurityEvent.is_simulated.is_(True)))}

# ---- Audit (read-only; there is deliberately no write/delete route)
@router.get("/audit")
def audit_list(p: int = 1, size: int = Query(50, le=200), action: str | None = None, db: Session = Depends(get_db), ctx: Ctx = Depends(require("security_admin"))):
    qry = db.query(AuditLog).filter_by(organization_id=ctx.org_id)
    if action: qry = qry.filter(AuditLog.action.like(f"{action}%"))
    r = page(qry.order_by(AuditLog.created_at.desc()), p, size); r["items"] = [row(a) for a in r["items"]]; return r

# ---- Demo data (simulated, clearly labeled; reset only removes is_simulated rows)
@router.post("/demo/load")
def demo_load(scenarios: list[str] | None = None, db: Session = Depends(get_db), ctx: Ctx = Depends(require("security_admin"))):
    if not settings.demo_mode: raise HTTPException(403, "Demo mode disabled")
    bad = [s for s in (scenarios or []) if s not in SCENARIOS]
    if bad: raise HTTPException(422, f"Unknown scenarios {bad}")
    job = IngestionJob(organization_id=ctx.org_id, fmt="json", filename="simulated-demo"); db.add(job); db.flush()
    for h, t, crit in (("web01", "server", "high"), ("db01", "server", "critical"), ("file01", "server", "high"), ("fw01", "network_device", "medium")):
        if not db.query(Asset).filter_by(organization_id=ctx.org_id, hostname=h).first():
            db.add(Asset(organization_id=ctx.org_id, name=f"[SIMULATED] {h}", hostname=h, asset_type=t, criticality=crit, is_simulated=True))
    ing.ingest_records(db, ctx.org_id, job, generate(scenarios or None), "simulated"); res = det.evaluate(db, ctx.org_id)
    audit(db, ctx, "demo.load", None, None, **res); db.commit(); return {**row(job), **res}

@router.post("/demo/reset")
def demo_reset(db: Session = Depends(get_db), ctx: Ctx = Depends(require("owner"))):
    o = ctx.org_id
    inc_ids = [i.id for i in db.query(Incident).filter_by(organization_id=o, is_simulated=True)]
    for m in (ResponseAction, AIAnalysis, InvestigationNote):
        if inc_ids: db.query(m).filter(m.organization_id == o, m.incident_id.in_(inc_ids)).delete(synchronize_session=False)
    n = {"alerts": db.query(Alert).filter_by(organization_id=o, is_simulated=True).delete(), "incidents": db.query(Incident).filter_by(organization_id=o, is_simulated=True).delete(),
         "events": db.query(SecurityEvent).filter_by(organization_id=o, is_simulated=True).delete(), "assets": db.query(Asset).filter_by(organization_id=o, is_simulated=True).delete()}
    audit(db, ctx, "demo.reset", None, None, **n); db.commit(); return n

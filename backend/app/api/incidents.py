"""Incidents, investigation (AI), response actions/approvals, reports."""
import csv, io, json, uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.core.db import get_db
from app.core.deps import Ctx, current_ctx, require
from app.models import *
from app.audit import audit
from app.ai.provider import analyze
from app.domain import response as R
from .schemas import IncidentPatch, NoteIn, ActionIn, DecisionIn
from .ops import _get, _uuid, row, page

router = APIRouter(prefix="/api")
FIREWALL = R.MockFirewall()   # simulation only

@router.get("/incidents")
def incidents(p: int = 1, size: int = Query(25, le=100), status: str | None = None, severity: str | None = None,
              db: Session = Depends(get_db), ctx: Ctx = Depends(current_ctx)):
    q = db.query(Incident).filter_by(organization_id=ctx.org_id)
    if status: q = q.filter_by(status=status)
    if severity: q = q.filter_by(severity=severity)
    r = page(q.order_by(Incident.created_at.desc()), p, size); r["items"] = [row(i) for i in r["items"]]; return r

def _incident_bundle(db, ctx, inc):
    alerts = db.query(Alert).filter_by(organization_id=ctx.org_id, incident_id=inc.id).all()
    ev_ids = [e.event_id for e in db.query(IncidentEvent).filter_by(incident_id=inc.id)]
    events = db.query(SecurityEvent).filter(SecurityEvent.organization_id == ctx.org_id, SecurityEvent.id.in_(ev_ids)).order_by(SecurityEvent.timestamp).all() if ev_ids else []
    return alerts, events

@router.get("/incidents/{incident_id}")
def incident_detail(incident_id: str, db: Session = Depends(get_db), ctx: Ctx = Depends(current_ctx)):
    inc = _get(db, Incident, incident_id, ctx); alerts, events = _incident_bundle(db, ctx, inc)
    notes = db.query(InvestigationNote).filter_by(organization_id=ctx.org_id, incident_id=inc.id).order_by(InvestigationNote.created_at).all()
    analyses = db.query(AIAnalysis).filter_by(organization_id=ctx.org_id, incident_id=inc.id).order_by(AIAnalysis.version.desc()).all()
    actions = db.query(ResponseAction).filter_by(organization_id=ctx.org_id, incident_id=inc.id).order_by(ResponseAction.created_at).all()
    audits = db.query(AuditLog).filter_by(organization_id=ctx.org_id, resource_type="incident", resource_id=str(inc.id)).order_by(AuditLog.created_at).all()
    timeline = sorted(
        [{"at": e.timestamp.isoformat(), "kind": "observed_event", "label": f"{e.action} ({e.result or '-'}) {e.username or ''}@{e.hostname or ''} from {e.source_ip or '-'}", "id": str(e.id)} for e in events] +
        [{"at": a.created_at.isoformat(), "kind": "detection", "label": a.title, "id": str(a.id)} for a in alerts] +
        [{"at": n.created_at.isoformat(), "kind": "analyst_action", "label": n.body[:120], "id": str(n.id)} for n in notes] +
        [{"at": x.created_at.isoformat(), "kind": "ai_analysis", "label": f"Analysis v{x.version} ({'LLM' if x.is_llm else 'rule-based, non-LLM'})", "id": str(x.id)} for x in analyses] +
        [{"at": x.created_at.isoformat(), "kind": "response", "label": f"{x.action_type}: {x.approval_status}/{x.execution_status}", "id": str(x.id)} for x in actions],
        key=lambda t: t["at"])
    return {**row(inc), "alerts": [row(a) for a in alerts], "events": [row(e) for e in events], "notes": [row(n) for n in notes],
            "analyses": [row(a) for a in analyses], "actions": [row(a) for a in actions], "audit": [row(a) for a in audits], "timeline": timeline}

@router.patch("/incidents/{incident_id}")
def incident_patch(incident_id: str, body: IncidentPatch, db: Session = Depends(get_db), ctx: Ctx = Depends(require("analyst"))):
    inc = _get(db, Incident, incident_id, ctx); before = inc.status
    if body.status: inc.status = body.status
    if body.title: inc.title = body.title
    if body.assigned_to:
        if not db.query(OrganizationMember).filter_by(organization_id=ctx.org_id, user_id=_uuid(body.assigned_to)).first(): raise HTTPException(422, "Assignee is not a member of this organization")
        inc.assigned_to = _uuid(body.assigned_to)
    audit(db, ctx, "incident.update", "incident", inc.id, from_status=before, to_status=inc.status); db.commit(); return row(inc)

@router.post("/incidents/{incident_id}/alerts/{alert_id}", status_code=204)
def link_alert(incident_id: str, alert_id: str, db: Session = Depends(get_db), ctx: Ctx = Depends(require("analyst"))):
    inc = _get(db, Incident, incident_id, ctx); a = _get(db, Alert, alert_id, ctx)
    if a.incident_id == inc.id: return
    if a.incident_id: db.query(IncidentAlert).filter_by(alert_id=a.id).delete()
    a.incident_id = inc.id; db.add(IncidentAlert(incident_id=inc.id, alert_id=a.id))
    for eid in a.event_ids:
        if not db.get(IncidentEvent, (inc.id, uuid.UUID(eid))): db.add(IncidentEvent(incident_id=inc.id, event_id=uuid.UUID(eid)))
    audit(db, ctx, "incident.link_alert", "incident", inc.id, alert_id=str(a.id)); db.commit()

@router.delete("/incidents/{incident_id}/alerts/{alert_id}", status_code=204)
def unlink_alert(incident_id: str, alert_id: str, db: Session = Depends(get_db), ctx: Ctx = Depends(require("analyst"))):
    inc = _get(db, Incident, incident_id, ctx); a = _get(db, Alert, alert_id, ctx)
    if a.incident_id != inc.id: raise HTTPException(404, "Alert is not linked to this incident")
    a.incident_id = None; db.query(IncidentAlert).filter_by(alert_id=a.id, incident_id=inc.id).delete()
    audit(db, ctx, "incident.unlink_alert", "incident", inc.id, alert_id=str(a.id)); db.commit()

@router.post("/incidents/{incident_id}/notes", status_code=201)
def add_note(incident_id: str, body: NoteIn, db: Session = Depends(get_db), ctx: Ctx = Depends(require("analyst"))):
    inc = _get(db, Incident, incident_id, ctx)
    n = InvestigationNote(organization_id=ctx.org_id, incident_id=inc.id, author_id=ctx.user_id, body=body.body); db.add(n); db.flush()
    audit(db, ctx, "incident.note_added", "incident", inc.id); db.commit(); return row(n)

# ---- AI analysis (versions preserved; regenerate = new version)
@router.post("/investigations/{incident_id}/analyze", status_code=201)
def run_analysis(incident_id: str, db: Session = Depends(get_db), ctx: Ctx = Depends(require("analyst"))):
    inc = _get(db, Incident, incident_id, ctx); alerts, events = _incident_bundle(db, ctx, inc)
    notes = [n.body for n in db.query(InvestigationNote).filter_by(organization_id=ctx.org_id, incident_id=inc.id)]
    rules = {str(r.id): {"name": r.name, "category": r.category} for r in db.query(DetectionRule).filter_by(organization_id=ctx.org_id)}
    a_ctx = [{"id": str(a.id), "title": a.title, "description": a.description, "category": a.category, "severity": a.severity,
              "rule": rules.get(str(a.rule_id)), "event_ids": a.event_ids} for a in alerts]
    e_ctx = [{"id": str(e.id), "timestamp": e.timestamp.isoformat(), "action": e.action, "result": e.result, "username": e.username,
              "hostname": e.hostname, "source_ip": e.source_ip, "destination_ip": e.destination_ip, "attributes": e.attributes} for e in events]
    assets = db.query(Asset).filter(Asset.organization_id == ctx.org_id, Asset.hostname.in_({e.hostname for e in events if e.hostname})).all() if events else []
    res = analyze({"title": inc.title, "severity": inc.severity, "status": inc.status, "assets": [row(a, "tags") for a in assets]}, a_ctx, e_ctx, notes)
    ver = (db.query(AIAnalysis).filter_by(incident_id=inc.id).count()) + 1
    rec = AIAnalysis(organization_id=ctx.org_id, incident_id=inc.id, version=ver, provider=res["provider"], model=res["model"], is_llm=res["is_llm"], content=res["content"], requested_by=ctx.user_id)
    db.add(rec); db.flush()
    # AI recommendations become PENDING proposals only; they are never executed automatically.
    for ra in res["content"].get("recommended_actions", []):
        try:
            a = R.request_action(str(uuid.uuid4()), str(ctx.org_id), str(inc.id), ra["action_type"], ra.get("params", {}), str(ctx.user_id), ctx.role, origin="ai")
        except R.ResponseError:
            continue  # invalid params from the model => dropped, not executed
        db.add(ResponseAction(organization_id=ctx.org_id, incident_id=inc.id, action_type=a.action_type, params=a.params, requested_by=ctx.user_id, origin="ai"))
    audit(db, ctx, "ai.analysis_requested", "incident", inc.id, version=ver, provider=res["provider"], is_llm=res["is_llm"]); db.commit(); return row(rec)

# ---- Response center
def _to_domain(a: ResponseAction) -> R.ResponseAction:
    return R.ResponseAction(str(a.id), str(a.organization_id), str(a.incident_id) if a.incident_id else None, a.action_type, a.params,
                            str(a.requested_by), a.approval_status, a.execution_status, None, a.result, a.origin)

@router.get("/response-actions")
def actions(status: str | None = None, p: int = 1, size: int = Query(25, le=100), db: Session = Depends(get_db), ctx: Ctx = Depends(current_ctx)):
    q = db.query(ResponseAction).filter_by(organization_id=ctx.org_id)
    if status: q = q.filter_by(approval_status=status)
    r = page(q.order_by(ResponseAction.created_at.desc()), p, size); r["items"] = [row(a) for a in r["items"]]; return r

@router.post("/response-actions", status_code=201)
def request_action(body: ActionIn, db: Session = Depends(get_db), ctx: Ctx = Depends(require("analyst"))):
    inc = _get(db, Incident, body.incident_id, ctx) if body.incident_id else None
    try: a = R.request_action(str(uuid.uuid4()), str(ctx.org_id), str(inc.id) if inc else None, body.action_type, body.params, str(ctx.user_id), ctx.role)
    except R.ResponseError as e: raise HTTPException(422, str(e))
    rec = ResponseAction(organization_id=ctx.org_id, incident_id=inc.id if inc else None, action_type=a.action_type, params=a.params, requested_by=ctx.user_id)
    db.add(rec); db.flush(); audit(db, ctx, "response.requested", "response_action", rec.id, action_type=a.action_type, params=a.params); db.commit(); return row(rec)

@router.post("/approvals/{action_id}")
def decide(action_id: str, body: DecisionIn, db: Session = Depends(get_db), ctx: Ctx = Depends(require("security_admin"))):
    rec = _get(db, ResponseAction, action_id, ctx)
    d = _to_domain(rec)
    try: R.decide(d, str(ctx.user_id), ctx.role, str(ctx.org_id), body.approve)
    except R.ResponseError as e: raise HTTPException(409, str(e))
    rec.approval_status = d.approval_status
    db.add(ResponseApproval(organization_id=ctx.org_id, action_id=rec.id, approver_id=ctx.user_id, approved=body.approve, comment=body.comment))
    audit(db, ctx, "response.approved" if body.approve else "response.rejected", "response_action", rec.id); db.commit(); return row(rec)

@router.post("/response-actions/{action_id}/execute")
def execute(action_id: str, db: Session = Depends(get_db), ctx: Ctx = Depends(require("security_admin"))):
    rec = db.query(ResponseAction).filter_by(id=_uuid(action_id), organization_id=ctx.org_id).with_for_update().first()   # row lock => idempotent under concurrency
    if not rec: raise HTTPException(404, "Not found")
    d = _to_domain(rec)
    handlers = {"acknowledge_alert": lambda p: _ack(db, ctx, p), "add_note": lambda p: _note(db, ctx, rec, p),
                "disable_detection_rule": lambda p: _disable(db, ctx, p), "assign_incident": lambda p: _assign(db, ctx, p),
                "generate_report": lambda p: {"message": "Use GET /api/reports/incidents/{id}"}, "create_recommendation": lambda p: {"recorded": True}}
    try: R.execute(d, str(ctx.org_id), FIREWALL, handlers)
    except R.ResponseError as e: raise HTTPException(409, str(e))
    first_run = rec.execution_status != "executed"
    rec.execution_status, rec.result = d.execution_status, d.result
    if first_run: db.add(ResponseExecution(organization_id=ctx.org_id, action_id=rec.id, status=d.execution_status, result=d.result or {}))
    audit(db, ctx, f"response.{d.execution_status}", "response_action", rec.id, simulated=bool((d.result or {}).get("simulated"))); db.commit(); return row(rec)

def _ack(db, ctx, p):
    a = _get(db, Alert, p["alert_id"], ctx); a.status = "acknowledged"; return {"alert_id": str(a.id), "status": "acknowledged"}
def _note(db, ctx, rec, p):
    db.add(InvestigationNote(organization_id=ctx.org_id, incident_id=rec.incident_id, author_id=ctx.user_id, body=p["note"])); return {"note_added": True}
def _disable(db, ctx, p):
    r = _get(db, DetectionRule, p["rule_id"], ctx); r.enabled = False; return {"rule": r.rule_key, "enabled": False}
def _assign(db, ctx, p):
    i = _get(db, Incident, p["incident_id"], ctx)
    if not db.query(OrganizationMember).filter_by(organization_id=ctx.org_id, user_id=_uuid(p["user_id"])).first(): raise R.ResponseError("assignee not in organization")
    i.assigned_to = _uuid(p["user_id"]); return {"assigned_to": p["user_id"]}

# ---- Reports (built strictly from stored records)
@router.get("/reports/incidents/{incident_id}")
def report(incident_id: str, fmt: str = Query("json", pattern="^(json|csv|pdf)$"), db: Session = Depends(get_db), ctx: Ctx = Depends(require("analyst"))):
    d = incident_detail(incident_id, db, ctx); inc = {k: d[k] for k in ("id", "title", "severity", "status", "description", "created_at")}
    latest = d["analyses"][0] if d["analyses"] else None
    doc = {"generated_at": datetime.now(timezone.utc).isoformat(), "incident": inc, "alerts": d["alerts"], "events": d["events"],
           "notes": d["notes"], "response_actions": d["actions"],
           "ai_analysis": {"label": "AI-GENERATED" if latest and latest["is_llm"] else "NON-LLM RULE-BASED", "version": latest["version"], "content": latest["content"]} if latest else None}
    audit(db, ctx, "report.generated", "incident", incident_id, fmt=fmt); db.commit()
    if fmt == "json": return Response(json.dumps(doc, default=str, indent=2), media_type="application/json")
    if fmt == "csv":
        buf = io.StringIO(); w = csv.writer(buf); w.writerow(["timestamp", "action", "result", "username", "hostname", "source_ip", "event_id"])
        for e in d["events"]: w.writerow([e["timestamp"], e["action"], e["result"], e["username"], e["hostname"], e["source_ip"], e["id"]])
        return Response(buf.getvalue(), media_type="text/csv")
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from xml.sax.saxutils import escape
    out = io.BytesIO(); s = getSampleStyleSheet(); parts = [Paragraph(escape(f"Incident report: {inc['title']}"), s["Title"]),
        Paragraph(escape(f"Severity {inc['severity']} | Status {inc['status']} | Generated {doc['generated_at']}"), s["Normal"]), Spacer(1, 12), Paragraph("Alerts", s["Heading2"])]
    parts += [Paragraph(escape(f"[{a['severity']}] {a['title']} - {a['description']}"), s["Normal"]) for a in d["alerts"]]
    parts += [Paragraph("Event evidence", s["Heading2"])] + [Paragraph(escape(f"{e['timestamp']} {e['action']} {e['result'] or ''} {e['source_ip'] or ''}"), s["Normal"]) for e in d["events"][:200]]
    parts += [Paragraph("Investigation notes", s["Heading2"])] + [Paragraph(escape(n["body"]), s["Normal"]) for n in d["notes"]]
    parts += [Paragraph("Response actions", s["Heading2"])] + [Paragraph(escape(f"{x['action_type']} {x['approval_status']}/{x['execution_status']}"), s["Normal"]) for x in d["actions"]]
    if latest: parts += [Paragraph(doc["ai_analysis"]["label"] + " analysis", s["Heading2"]), Paragraph(escape(str(latest["content"].get("executive_summary", ""))), s["Normal"])]
    SimpleDocTemplate(out, pagesize=A4).build(parts)
    return Response(out.getvalue(), media_type="application/pdf")

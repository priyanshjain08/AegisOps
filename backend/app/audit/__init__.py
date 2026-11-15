from sqlalchemy.orm import Session
from app.models import AuditLog

def audit(db: Session, ctx_or_none, action: str, resource_type: str | None = None, resource_id=None,
          org_id=None, actor_id=None, request_id=None, **meta):
    """Append-only. No update/delete API exists for audit rows; callers pass non-secret metadata only."""
    db.add(AuditLog(organization_id=org_id or getattr(ctx_or_none, "org_id", None),
                    actor_id=actor_id or getattr(ctx_or_none, "user_id", None), action=action,
                    resource_type=resource_type, resource_id=str(resource_id) if resource_id else None,
                    meta=meta, request_id=request_id or getattr(ctx_or_none, "request_id", None)))

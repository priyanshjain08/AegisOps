import uuid
from dataclasses import dataclass
import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from .db import get_db
from .security import decode_access_token
from app.models import OrganizationMember, User

bearer = HTTPBearer(auto_error=False)
ROLE_RANK = {"viewer": 1, "analyst": 2, "security_admin": 3, "owner": 4}

@dataclass
class Ctx:
    user_id: uuid.UUID
    org_id: uuid.UUID
    role: str
    request_id: str

def current_ctx(request: Request, cred: HTTPAuthorizationCredentials | None = Depends(bearer),
                db: Session = Depends(get_db)) -> Ctx:
    if cred is None:
        raise HTTPException(401, "Missing bearer token")
    try:
        d = decode_access_token(cred.credentials)
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
    # Re-check membership on every request so role changes / removals take effect immediately.
    m = db.query(OrganizationMember).filter_by(user_id=uuid.UUID(d["sub"]), organization_id=uuid.UUID(d["org"])).first()
    user = db.get(User, uuid.UUID(d["sub"]))
    if not m or not user or not user.is_active:
        raise HTTPException(401, "Membership no longer valid")
    return Ctx(user.id, m.organization_id, m.role, getattr(request.state, "request_id", ""))

def require(min_role: str):
    def dep(ctx: Ctx = Depends(current_ctx)) -> Ctx:
        if ROLE_RANK[ctx.role] < ROLE_RANK[min_role]:
            raise HTTPException(403, f"Requires role {min_role} or higher")
        return ctx
    return dep

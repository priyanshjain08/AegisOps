import uuid
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.db import get_db
from app.core.config import settings
from app.core import security as sec
from app.core.deps import Ctx, current_ctx
from app.models import User, Organization, OrganizationMember, RefreshToken
from app.audit import audit
from .schemas import RegisterIn, LoginIn, RefreshIn

router = APIRouter(prefix="/api/auth", tags=["auth"])

def _issue(db, user, org_id, role):
    raw, h = sec.new_refresh_token()
    rt = RefreshToken(user_id=user.id, org_id=org_id, token_hash=h, expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_days))
    db.add(rt); db.flush()
    return {"access_token": sec.make_access_token(user.id, org_id, role), "refresh_token": raw, "token_type": "bearer", "role": role}, rt

@router.post("/register", status_code=201)
def register(body: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter_by(email=body.email.lower()).first():
        raise HTTPException(409, "Email already registered")
    user = User(email=body.email.lower(), password_hash=sec.hash_password(body.password), full_name=body.full_name)
    org = Organization(name=body.organization_name); db.add_all([user, org]); db.flush()
    db.add(OrganizationMember(organization_id=org.id, user_id=user.id, role="owner"))
    tokens, _ = _issue(db, user, org.id, "owner")
    audit(db, None, "auth.register", "user", user.id, org_id=org.id, actor_id=user.id)
    db.commit(); return tokens

@router.post("/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=body.email.lower()).first()
    m = db.query(OrganizationMember).filter_by(user_id=user.id).first() if user else None
    if not user or not m or not user.is_active or not sec.verify_password(body.password, user.password_hash):
        audit(db, None, "auth.login_failed", "user", user.id if user else None, org_id=m.organization_id if m else None, email=body.email)
        db.commit(); raise HTTPException(401, "Invalid credentials")
    tokens, _ = _issue(db, user, m.organization_id, m.role)
    audit(db, None, "auth.login", "user", user.id, org_id=m.organization_id, actor_id=user.id); db.commit(); return tokens

@router.post("/refresh")
def refresh(body: RefreshIn, db: Session = Depends(get_db)):
    rt = db.query(RefreshToken).filter_by(token_hash=sec.hash_refresh(body.refresh_token)).first()
    if not rt:
        raise HTTPException(401, "Invalid refresh token")
    if rt.revoked_at is not None:
        # Reuse of a rotated token => assume theft; revoke the user's whole token family.
        db.query(RefreshToken).filter_by(user_id=rt.user_id, revoked_at=None).update({"revoked_at": datetime.now(timezone.utc)})
        audit(db, None, "auth.refresh_reuse_detected", "user", rt.user_id, org_id=rt.org_id); db.commit()
        raise HTTPException(401, "Refresh token reuse detected; sessions revoked")
    if rt.expires_at < datetime.now(timezone.utc):
        raise HTTPException(401, "Refresh token expired")
    m = db.query(OrganizationMember).filter_by(user_id=rt.user_id, organization_id=rt.org_id).first()
    if not m: raise HTTPException(401, "Membership no longer valid")
    user = db.get(User, rt.user_id)
    tokens, new_rt = _issue(db, user, rt.org_id, m.role)
    rt.revoked_at, rt.replaced_by = datetime.now(timezone.utc), new_rt.id
    db.commit(); return tokens

@router.post("/logout", status_code=204)
def logout(body: RefreshIn, db: Session = Depends(get_db), ctx: Ctx = Depends(current_ctx)):
    rt = db.query(RefreshToken).filter_by(token_hash=sec.hash_refresh(body.refresh_token), user_id=ctx.user_id).first()
    if rt and rt.revoked_at is None: rt.revoked_at = datetime.now(timezone.utc)
    audit(db, ctx, "auth.logout", "user", ctx.user_id); db.commit()

@router.get("/me")
def me(db: Session = Depends(get_db), ctx: Ctx = Depends(current_ctx)):
    u = db.get(User, ctx.user_id); o = db.get(Organization, ctx.org_id)
    return {"id": str(u.id), "email": u.email, "full_name": u.full_name, "role": ctx.role,
            "organization": {"id": str(o.id), "name": o.name, "is_demo": o.is_demo}}

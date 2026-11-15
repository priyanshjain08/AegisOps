import hashlib, secrets, uuid
from datetime import datetime, timedelta, timezone
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from .config import settings

_ph = PasswordHasher()

def hash_password(pw: str) -> str: return _ph.hash(pw)
def verify_password(pw: str, h: str) -> bool:
    try: return _ph.verify(h, pw)
    except VerifyMismatchError: return False

def make_access_token(user_id: uuid.UUID, org_id: uuid.UUID, role: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": str(user_id), "org": str(org_id), "role": role, "type": "access",
                       "iat": now, "exp": now + timedelta(minutes=settings.access_token_minutes)},
                      settings.jwt_secret, algorithm="HS256")

def decode_access_token(token: str) -> dict:
    data = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    if data.get("type") != "access":
        raise jwt.InvalidTokenError("wrong token type")
    return data

def new_refresh_token() -> tuple[str, str]:
    """Returns (opaque token for client, sha256 hash for storage). Raw token is never stored."""
    raw = secrets.token_urlsafe(48)
    return raw, hashlib.sha256(raw.encode()).hexdigest()

def hash_refresh(raw: str) -> str: return hashlib.sha256(raw.encode()).hexdigest()

import uuid, logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from app.core.config import settings
from app.api import auth, ops, incidents

logging.basicConfig(level=logging.INFO)
limiter = Limiter(key_func=get_remote_address, default_limits=["300/minute"], storage_uri=settings.redis_url)
app = FastAPI(title="AegisOps API", version="0.1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in settings.cors_origins.split(",")],
                   allow_credentials=True, allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type"])

@app.middleware("http")
async def request_id(request: Request, call_next):
    request.state.request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    resp = await call_next(request); resp.headers["x-request-id"] = request.state.request_id
    resp.headers["x-content-type-options"] = "nosniff"; return resp

app.include_router(auth.router); app.include_router(ops.router); app.include_router(incidents.router)

@app.get("/health")
def health(): return {"status": "ok"}

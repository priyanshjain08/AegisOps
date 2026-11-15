import csv, io, json
from datetime import datetime, timezone
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session
from app.models import SecurityEvent, IngestionJob
from app.domain.events import normalize_batch

def parse_payload(fmt: str, data: bytes) -> list:
    text = data.decode("utf-8-sig")
    if fmt == "json":
        obj = json.loads(text)
        return obj if isinstance(obj, list) else obj.get("events", [obj])
    if fmt == "jsonl":
        out = []
        for i, line in enumerate(text.splitlines()):
            if line.strip():
                try: out.append(json.loads(line))
                except json.JSONDecodeError as e: out.append({"__parse_error__": f"line {i+1}: {e}"})
        return out
    if fmt == "csv":
        return list(csv.DictReader(io.StringIO(text)))
    raise ValueError(f"unsupported format {fmt}")

def ingest_records(db: Session, org_id, job: IngestionJob, records: list, source_type="generic", source_id=None):
    job.status, job.total = "processing", len(records)
    clean, pre_err = [], []
    for i, r in enumerate(records):
        if isinstance(r, dict) and "__parse_error__" in r:
            pre_err.append({"index": i, "error": r["__parse_error__"]})
        else:
            clean.append(r)
    events, errors = normalize_batch(clean, source_type)
    errors = pre_err + errors
    accepted = 0
    for e in events:
        stmt = insert(SecurityEvent).values(organization_id=org_id, source_id=source_id, job_id=job.id, timestamp=e.timestamp,
            source_type=e.source_type, hostname=e.hostname, username=e.username, source_ip=e.source_ip,
            destination_ip=e.destination_ip, category=e.category, action=e.action, severity=e.severity, result=e.result,
            raw=e.raw, attributes=e.attributes, dedup_hash=e.dedup_hash, is_simulated=bool(e.raw.get("simulated"))
        ).on_conflict_do_nothing(constraint=None, index_elements=["organization_id", "dedup_hash"])
        if db.execute(stmt).rowcount:
            accepted += 1
        else:
            errors.append({"index": None, "error": "duplicate of previously ingested event"})
    job.accepted, job.rejected = accepted, job.total - accepted
    job.errors = errors[:500]
    job.status, job.finished_at = "completed", datetime.now(timezone.utc)
    db.flush()
    return job

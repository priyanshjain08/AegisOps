import uuid
from app.workers.celery_app import celery
from app.core.db import SessionLocal
from app.models import IngestionJob
from app.services import ingest_service as ing, detection_service as det

@celery.task(name="ingest_task")
def ingest_task(org_id: str, job_id: str, records: list, source_type: str):
    db = SessionLocal()
    try:
        job = db.get(IngestionJob, uuid.UUID(job_id))
        try:
            ing.ingest_records(db, uuid.UUID(org_id), job, records, source_type); det.evaluate(db, uuid.UUID(org_id)); db.commit()
        except Exception as e:                       # failures are recorded on the job, never silent
            db.rollback(); job = db.get(IngestionJob, uuid.UUID(job_id)); job.status = "failed"; job.errors = [{"error": str(e)}]; db.commit(); raise
    finally:
        db.close()

from celery import Celery
from app.core.config import settings
celery = Celery("aegisops", broker=settings.redis_url, backend=settings.redis_url, include=["app.workers.tasks"])
celery.conf.task_time_limit = 600

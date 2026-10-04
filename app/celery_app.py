import os
from celery import Celery

REDIS_URL = os.getenv("REDIS_URL", "redis://aegis-redis:6379/0")

celery_app = Celery(
    "aegis_worker",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=[
        "app.tasks.recon", 
        "app.tasks.port_scan", 
        "app.tasks.ai_triage", 
        "app.tasks.fuzzing", 
        "app.tasks.active_scanner"  # Added active scanner
    ]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)
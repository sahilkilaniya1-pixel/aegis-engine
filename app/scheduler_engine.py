from celery import Celery
from celery.schedules import crontab
from app.tasks.active_scanner import run_active_vulnerability_scan
from app.database import SessionLocal
from app.models import Target

celery_app = Celery("aegis_scheduler", broker="redis://localhost:6379/0")

celery_app.conf.beat_schedule = {
    'weekly-security-scan-every-monday': {
        'task': 'app.scheduler_engine.scheduled_target_scan',
        'schedule': crontab(hour=2, minute=0, day_of_week=1), # Every Monday at 2:00 AM
    },
}

@celery_app.task
def scheduled_target_scan():
    db = SessionLocal()
    try:
        targets = db.query(Target).all()
        for target in targets:
            # Automatically trigger background security scan for all registered enterprise targets
            run_active_vulnerability_scan.delay(None, target.id, target.domain)
    finally:
        db.close()
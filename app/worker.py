"""Celery application used by the API for dispatch and by the background worker."""

from celery import Celery

import app.models  # noqa: F401  Register every mapper before tasks query the database.
from app.core.config import Settings, get_settings
from app.core.logging import install_redaction

TASK_MODULES = ["app.email.tasks"]


def create_celery_app(settings: Settings | None = None) -> Celery:
    """Create a Celery application that uses Redis as broker and result backend."""
    resolved_settings = settings or get_settings()
    redis_url = resolved_settings.redis_url.get_secret_value()

    application = Celery("auth", broker=redis_url, backend=redis_url, include=TASK_MODULES)
    application.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        # Acknowledge after execution so a crashed worker's task is redelivered.
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        # Email tasks report outcomes through logs; results are not consumed by the API.
        task_ignore_result=True,
        result_expires=3600,
        # Never persist task arguments in the result backend; they may hold raw tokens.
        result_extended=False,
        broker_connection_retry_on_startup=True,
        # Bound publish retries so an unavailable broker fails the request promptly.
        task_publish_retry=True,
        task_publish_retry_policy={
            "max_retries": 3,
            "interval_start": 0,
            "interval_step": 0.2,
            "interval_max": 0.5,
        },
        task_always_eager=resolved_settings.celery_task_always_eager,
        # Like a real worker, eager tasks retry and report failures without raising
        # into the caller; inspect the returned result to observe the outcome.
        task_eager_propagates=False,
    )
    return application


install_redaction()
celery_app = create_celery_app()

"""Celery application configuration tests."""

import subprocess
import sys

from app.core.config import Environment, Settings
from app.worker import celery_app, create_celery_app


def test_celery_uses_configured_redis_for_broker_and_results() -> None:
    settings = Settings.model_validate(
        {"environment": Environment.TEST, "redis_url": "redis://redis.internal:6380/2"}
    )

    application = create_celery_app(settings)

    assert application.conf.broker_url == "redis://redis.internal:6380/2"
    assert application.conf.result_backend == "redis://redis.internal:6380/2"
    assert application.conf.task_always_eager is False


def test_celery_is_configured_for_safe_retries() -> None:
    conf = create_celery_app(Settings.model_validate({"environment": Environment.TEST})).conf

    assert conf.accept_content == ["json"]
    assert conf.task_serializer == "json"
    assert conf.task_acks_late is True
    assert conf.task_reject_on_worker_lost is True
    assert conf.result_extended is False
    assert conf.task_publish_retry_policy["max_retries"] == 3


def test_worker_registers_email_tasks() -> None:
    celery_app.loader.import_default_modules()

    assert {
        "auth.email.send_verification_email",
        "auth.email.send_password_reset_email",
    } <= set(celery_app.tasks)


def test_worker_import_configures_all_mappers_in_a_fresh_process() -> None:
    script = (
        "import app.worker, app.email.tasks; "
        "from sqlalchemy.orm import configure_mappers; configure_mappers()"
    )

    completed = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=False
    )

    assert completed.returncode == 0, completed.stderr

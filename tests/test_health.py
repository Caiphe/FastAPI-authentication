"""Health endpoint tests."""

from fastapi.testclient import TestClient

from app.core.config import Environment, Settings
from app.main import create_app


def test_health_endpoint() -> None:
    settings = Settings.model_validate({"environment": Environment.TEST})
    application = create_app(settings)

    with TestClient(application) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["content-type"] == "application/json"

"""Database infrastructure and metadata tests."""

from unittest.mock import Mock

import pytest
from sqlalchemy.orm import Session, configure_mappers

from app import models
from app.core import database


def test_metadata_contains_authentication_tables() -> None:
    configure_mappers()
    assert set(database.Base.metadata.tables) == {
        "action_tokens",
        "refresh_tokens",
        "users",
    }
    assert models.User.__tablename__ == "users"


def test_session_dependency_closes_after_success(monkeypatch: pytest.MonkeyPatch) -> None:
    session = Mock(spec=Session)
    monkeypatch.setattr(database, "SessionFactory", lambda: session)
    dependency = database.get_db_session()

    assert next(dependency) is session
    with pytest.raises(StopIteration):
        next(dependency)

    session.rollback.assert_not_called()
    session.close.assert_called_once_with()


def test_session_dependency_rolls_back_and_closes_on_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = Mock(spec=Session)
    monkeypatch.setattr(database, "SessionFactory", lambda: session)
    dependency = database.get_db_session()
    next(dependency)

    with pytest.raises(RuntimeError, match="database operation failed"):
        dependency.throw(RuntimeError("database operation failed"))

    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()

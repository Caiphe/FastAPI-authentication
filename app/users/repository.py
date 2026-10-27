"""Persistence operations for users."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.users.models import User


def get_user_by_email(session: Session, email: str) -> User | None:
    """Look up a user by an already-normalized email address."""
    return session.scalars(select(User).where(User.email == email)).one_or_none()


def get_user_by_id(session: Session, user_id: UUID) -> User | None:
    return session.get(User, user_id)


def add_user(session: Session, *, email: str, hashed_password: str) -> User:
    """Stage a new active, unverified user and assign its identifier."""
    user = User(email=email, hashed_password=hashed_password, is_active=True, is_verified=False)
    session.add(user)
    session.flush()
    return user

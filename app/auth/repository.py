"""Persistence operations for authentication tokens."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session, joinedload

from app.auth.models import ActionToken, ActionTokenPurpose, RefreshToken


def get_action_token(session: Session, token_id: UUID) -> ActionToken | None:
    """Load an action token together with its owning user."""
    statement = (
        select(ActionToken).options(joinedload(ActionToken.user)).where(ActionToken.id == token_id)
    )
    return session.scalars(statement).one_or_none()


def get_action_token_by_hash_for_update(session: Session, token_hash: str) -> ActionToken | None:
    """Load and row-lock an action token so concurrent consumers are serialized."""
    statement = (
        select(ActionToken)
        .options(joinedload(ActionToken.user))
        .where(ActionToken.token_hash == token_hash)
        .with_for_update(of=ActionToken)
    )
    return session.scalars(statement).one_or_none()


def add_action_token(
    session: Session,
    *,
    user_id: UUID,
    purpose: ActionTokenPurpose,
    token_hash: str,
    expires_at: datetime,
) -> ActionToken:
    """Stage a new action token and assign its identifier."""
    token = ActionToken(
        user_id=user_id,
        purpose=purpose,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    session.add(token)
    session.flush()
    return token


def delete_unused_action_tokens(
    session: Session,
    *,
    user_id: UUID,
    purpose: ActionTokenPurpose,
    keep_token_id: UUID | None = None,
) -> None:
    """Invalidate every outstanding token of one purpose for a user.

    ``keep_token_id`` excludes a token being consumed in the same transaction,
    whose pending ``used_at`` change may not have been flushed yet.
    """
    statement = delete(ActionToken).where(
        ActionToken.user_id == user_id,
        ActionToken.purpose == purpose,
        ActionToken.used_at.is_(None),
    )
    if keep_token_id is not None:
        statement = statement.where(ActionToken.id != keep_token_id)
    session.execute(statement)


def add_refresh_token(
    session: Session,
    *,
    user_id: UUID,
    family_id: UUID,
    token_hash: str,
    expires_at: datetime,
) -> RefreshToken:
    """Stage a hashed refresh token in a token family."""
    token = RefreshToken(
        user_id=user_id,
        family_id=family_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    session.add(token)
    session.flush()
    return token


def get_refresh_token_by_hash(session: Session, token_hash: str) -> RefreshToken | None:
    return session.scalars(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    ).one_or_none()


def get_refresh_token_by_hash_for_update(session: Session, token_hash: str) -> RefreshToken | None:
    """Load and row-lock a refresh token so concurrent rotations are serialized.

    ``populate_existing`` ensures a request that waited on the lock sees the
    state committed by the request that held it.
    """
    statement = (
        select(RefreshToken)
        .options(joinedload(RefreshToken.user))
        .where(RefreshToken.token_hash == token_hash)
        .with_for_update(of=RefreshToken)
        .execution_options(populate_existing=True)
    )
    return session.scalars(statement).one_or_none()


def revoke_refresh_token_family(session: Session, family_id: UUID, revoked_at: datetime) -> None:
    """Revoke every not-yet-revoked token in a family."""
    session.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=revoked_at)
    )


def revoke_user_refresh_tokens(session: Session, user_id: UUID, revoked_at: datetime) -> None:
    """Revoke every not-yet-revoked token in every family belonging to a user."""
    session.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=revoked_at)
    )

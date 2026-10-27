"""Delivery ledger that keeps email tasks idempotent across retries and redelivery."""

from functools import lru_cache
from typing import Protocol

from redis import Redis

from app.core.config import get_settings

KEY_PREFIX = "auth:email-delivery:"
# A claim outlives any single send attempt but expires if a worker dies mid-send,
# letting the redelivered task try again.
CLAIM_TTL_SECONDS = 300


class DeliveryLedger(Protocol):
    """Atomically claims and records action-token email deliveries."""

    def claim(self, key: str) -> bool:
        """Reserve a delivery; return False if it is in progress or already done."""
        ...

    def release(self, key: str) -> None:
        """Abandon a claim after a failed send so a retry can claim it again."""
        ...

    def mark_delivered(self, key: str, ttl_seconds: int) -> None:
        """Record a completed delivery until the related token expires."""
        ...


class RedisDeliveryLedger:
    """Store delivery claims and markers in Redis."""

    def __init__(self, client: Redis) -> None:
        self._client = client

    def claim(self, key: str) -> bool:
        return bool(self._client.set(KEY_PREFIX + key, "pending", nx=True, ex=CLAIM_TTL_SECONDS))

    def release(self, key: str) -> None:
        self._client.delete(KEY_PREFIX + key)

    def mark_delivered(self, key: str, ttl_seconds: int) -> None:
        self._client.set(KEY_PREFIX + key, "delivered", ex=max(ttl_seconds, CLAIM_TTL_SECONDS))


@lru_cache
def get_delivery_ledger() -> DeliveryLedger:
    """Return the worker-wide ledger backed by the configured Redis instance."""
    return RedisDeliveryLedger(Redis.from_url(get_settings().redis_url.get_secret_value()))

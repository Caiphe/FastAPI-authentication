"""Redis delivery-ledger tests against the Redis service from compose.yaml."""

from collections.abc import Iterator
from typing import cast
from uuid import uuid4

import pytest
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from app.core.config import get_settings
from app.email.ledger import CLAIM_TTL_SECONDS, KEY_PREFIX, RedisDeliveryLedger

pytestmark = pytest.mark.integration


def remaining_ttl(client: Redis, key: str) -> int:
    return cast(int, client.ttl(KEY_PREFIX + key))


@pytest.fixture
def redis_client() -> Iterator[Redis]:
    client = Redis.from_url(get_settings().redis_url.get_secret_value())
    try:
        client.ping()
    except RedisConnectionError as error:
        pytest.skip(f"Redis is unavailable for integration tests: {error}")
    yield client
    client.close()


@pytest.fixture
def key(redis_client: Redis) -> Iterator[str]:
    value = f"test-{uuid4()}"
    yield value
    redis_client.delete(KEY_PREFIX + value)


def test_only_one_claim_succeeds(redis_client: Redis, key: str) -> None:
    first, second = RedisDeliveryLedger(redis_client), RedisDeliveryLedger(redis_client)

    assert first.claim(key) is True
    assert second.claim(key) is False
    assert 0 < remaining_ttl(redis_client, key) <= CLAIM_TTL_SECONDS


def test_released_claim_can_be_claimed_again(redis_client: Redis, key: str) -> None:
    ledger = RedisDeliveryLedger(redis_client)
    ledger.claim(key)

    ledger.release(key)

    assert ledger.claim(key) is True


def test_delivered_marker_blocks_claims_until_token_expiry(redis_client: Redis, key: str) -> None:
    ledger = RedisDeliveryLedger(redis_client)
    ledger.claim(key)

    ledger.mark_delivered(key, ttl_seconds=3600)

    assert ledger.claim(key) is False
    assert 3500 < remaining_ttl(redis_client, key) <= 3600

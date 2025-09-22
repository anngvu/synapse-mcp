"""Session storage factory and exports."""

import logging
import os
from typing import Optional

from .base import SessionStorage
from .memory import InMemorySessionStorage
from .redis_backend import REDIS_AVAILABLE, RedisSessionStorage

logger = logging.getLogger("synapse_mcp.session_storage")


def create_session_storage(env: Optional[dict[str, str]] = None) -> SessionStorage:
    """Create appropriate session storage based on configuration."""
    env = env or os.environ
    redis_url = env.get("REDIS_URL")

    if redis_url and REDIS_AVAILABLE:
        logger.info("Using Redis session storage: %s", _redact_redis_url(redis_url))
        return RedisSessionStorage(redis_url)

    if redis_url and not REDIS_AVAILABLE:
        logger.warning("REDIS_URL provided but Redis not available - using in-memory storage")
    else:
        logger.info("No REDIS_URL configured - using in-memory storage")

    return InMemorySessionStorage()


def _redact_redis_url(redis_url: str) -> str:
    if "@" in redis_url:
        return redis_url.split("@", 1)[-1]
    return redis_url


__all__ = [
    "SessionStorage",
    "InMemorySessionStorage",
    "RedisSessionStorage",
    "create_session_storage",
]

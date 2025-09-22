"""
Redis-based session storage for scalable OAuth token management.

This module provides Redis-backed storage for session-to-token mappings,
enabling horizontal scaling and persistence across server restarts.
"""

import os
import json
import logging
import asyncio
from typing import Optional, Dict, Any, Set
from datetime import datetime, timedelta

logger = logging.getLogger("synapse_mcp.session_storage")

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("Redis not available - falling back to in-memory storage")


class SessionStorage:
    """Abstract base class for user-subject-based token storage implementations."""

    async def set_user_token(self, user_subject: str, access_token: str, ttl_seconds: int = 3600):
        """Store user-subject-to-token mapping with TTL."""
        raise NotImplementedError

    async def get_user_token(self, user_subject: str) -> Optional[str]:
        """Get access token for a user subject."""
        raise NotImplementedError

    async def remove_user_token(self, user_subject: str):
        """Remove user and its token mapping."""
        raise NotImplementedError

    async def cleanup_expired_tokens(self):
        """Clean up expired tokens."""
        raise NotImplementedError

    async def get_all_user_subjects(self) -> Set[str]:
        """Get all active user subjects."""
        raise NotImplementedError

    async def find_user_by_token(self, access_token: str) -> Optional[str]:
        """Find user subject by access token (reverse lookup)."""
        raise NotImplementedError


class RedisSessionStorage(SessionStorage):
    """Redis-based session storage for production deployments."""

    def __init__(self, redis_url: str, key_prefix: str = "synapse_mcp:session"):
        """
        Initialize Redis session storage.

        Args:
            redis_url: Redis connection URL (e.g., redis://user:pass@host:port)
            key_prefix: Prefix for Redis keys to avoid conflicts
        """
        if not REDIS_AVAILABLE:
            raise RuntimeError("Redis dependency not available")

        self.redis_url = redis_url
        self.key_prefix = key_prefix
        self._redis = None

        # Keys for different data types
        self.user_token_key = f"{key_prefix}:user_token"        # user_subject -> access_token
        self.token_user_key = f"{key_prefix}:token_user"        # access_token -> user_subject
        self.token_metadata_key = f"{key_prefix}:metadata"      # access_token -> {created_at, expires_at, user_subject}

    async def _get_redis(self):
        """Get Redis connection with lazy initialization."""
        if self._redis is None:
            try:
                self._redis = redis.from_url(
                    self.redis_url,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    health_check_interval=30
                )
                # Test connection
                await self._redis.ping()
                logger.info("Redis connection established")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
                raise

        return self._redis

    async def set_user_token(self, user_subject: str, access_token: str, ttl_seconds: int = 3600):
        """Store user-subject-to-token mapping with TTL."""
        try:
            redis_client = await self._get_redis()

            # Create metadata for the token
            metadata = {
                "created_at": datetime.utcnow().isoformat(),
                "expires_at": (datetime.utcnow() + timedelta(seconds=ttl_seconds)).isoformat(),
                "user_subject": user_subject
            }

            # Use pipeline for atomic operations
            async with redis_client.pipeline() as pipe:
                # Map user subject to token
                await pipe.hset(self.user_token_key, user_subject, access_token)
                await pipe.expire(self.user_token_key, ttl_seconds + 300)  # Extra buffer

                # Map token to user subject (for reverse lookup)
                await pipe.hset(self.token_user_key, access_token, user_subject)
                await pipe.expire(self.token_user_key, ttl_seconds + 300)

                # Store token metadata
                await pipe.hset(self.token_metadata_key, access_token, json.dumps(metadata))
                await pipe.expire(self.token_metadata_key, ttl_seconds + 300)

                await pipe.execute()

            logger.debug(f"Stored user {user_subject} -> token {access_token[:20]}*** in Redis")

        except Exception as e:
            logger.error(f"Failed to store user token in Redis: {e}")
            raise

    async def get_user_token(self, user_subject: str) -> Optional[str]:
        """Get access token for a user subject."""
        try:
            redis_client = await self._get_redis()
            access_token = await redis_client.hget(self.user_token_key, user_subject)

            if access_token:
                logger.debug(f"Retrieved token for user {user_subject} from Redis")
                return access_token

            return None

        except Exception as e:
            logger.error(f"Failed to get user token from Redis: {e}")
            return None

    async def remove_user_token(self, user_subject: str):
        """Remove user and its token mapping."""
        try:
            redis_client = await self._get_redis()

            # Get the token first so we can clean up reverse mappings
            access_token = await redis_client.hget(self.user_token_key, user_subject)

            if access_token:
                async with redis_client.pipeline() as pipe:
                    # Remove user -> token mapping
                    await pipe.hdel(self.user_token_key, user_subject)

                    # Remove token -> user mapping
                    await pipe.hdel(self.token_user_key, access_token)

                    # Remove token metadata
                    await pipe.hdel(self.token_metadata_key, access_token)

                    await pipe.execute()

                logger.debug(f"Removed user {user_subject} and token {access_token[:20]}*** from Redis")

        except Exception as e:
            logger.error(f"Failed to remove user token from Redis: {e}")

    async def cleanup_expired_tokens(self):
        """Clean up expired tokens based on metadata."""
        try:
            redis_client = await self._get_redis()

            # Get all token metadata
            all_metadata = await redis_client.hgetall(self.token_metadata_key)

            current_time = datetime.utcnow()
            expired_tokens = []

            for access_token, metadata_json in all_metadata.items():
                try:
                    metadata = json.loads(metadata_json)
                    expires_at = datetime.fromisoformat(metadata["expires_at"])

                    if expires_at < current_time:
                        expired_tokens.append(access_token)
                        user_subject = metadata.get("user_subject")
                        if user_subject:
                            await self.remove_user_token(user_subject)

                except Exception as e:
                    logger.warning(f"Error processing token metadata: {e}")
                    expired_tokens.append(access_token)

            if expired_tokens:
                logger.info(f"Cleaned up {len(expired_tokens)} expired tokens from Redis")

        except Exception as e:
            logger.error(f"Failed to cleanup expired tokens in Redis: {e}")

    async def get_all_user_subjects(self) -> Set[str]:
        """Get all active user subjects."""
        try:
            redis_client = await self._get_redis()
            user_subjects = await redis_client.hkeys(self.user_token_key)
            return set(user_subjects)
        except Exception as e:
            logger.error(f"Failed to get all user subjects from Redis: {e}")
            return set()

    async def find_user_by_token(self, access_token: str) -> Optional[str]:
        """Find user subject by access token (reverse lookup)."""
        try:
            redis_client = await self._get_redis()
            user_subject = await redis_client.hget(self.token_user_key, access_token)
            return user_subject
        except Exception as e:
            logger.error(f"Failed to find user by token in Redis: {e}")
            return None

    async def close(self):
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            logger.debug("Redis connection closed")


class InMemorySessionStorage(SessionStorage):
    """Fallback in-memory user-subject-based storage for development."""

    def __init__(self):
        self._user_tokens = {}  # user_subject -> access_token
        self._token_users = {}  # access_token -> user_subject
        self._token_metadata = {}  # access_token -> metadata

    async def set_user_token(self, user_subject: str, access_token: str, ttl_seconds: int = 3600):
        """Store user-subject-to-token mapping with TTL."""
        metadata = {
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(seconds=ttl_seconds)).isoformat(),
            "user_subject": user_subject
        }

        # Clean up any existing mapping for this user
        old_token = self._user_tokens.get(user_subject)
        if old_token:
            self._token_users.pop(old_token, None)
            self._token_metadata.pop(old_token, None)

        # Store new mappings
        self._user_tokens[user_subject] = access_token
        self._token_users[access_token] = user_subject
        self._token_metadata[access_token] = metadata

        logger.debug(f"Stored user {user_subject} -> token {access_token[:20]}*** in memory")

    async def get_user_token(self, user_subject: str) -> Optional[str]:
        """Get access token for a user subject."""
        return self._user_tokens.get(user_subject)

    async def remove_user_token(self, user_subject: str):
        """Remove user and its token mapping."""
        access_token = self._user_tokens.pop(user_subject, None)
        if access_token:
            self._token_users.pop(access_token, None)
            self._token_metadata.pop(access_token, None)
            logger.debug(f"Removed user {user_subject} from memory")

    async def cleanup_expired_tokens(self):
        """Clean up expired tokens based on metadata."""
        current_time = datetime.utcnow()
        expired_tokens = []

        for access_token, metadata in self._token_metadata.items():
            try:
                expires_at = datetime.fromisoformat(metadata["expires_at"])
                if expires_at < current_time:
                    expired_tokens.append(access_token)
            except Exception as e:
                logger.warning(f"Error processing token metadata: {e}")
                expired_tokens.append(access_token)

        for access_token in expired_tokens:
            user_subject = self._token_users.get(access_token)
            if user_subject:
                await self.remove_user_token(user_subject)

        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired tokens from memory")

    async def get_all_user_subjects(self) -> Set[str]:
        """Get all active user subjects."""
        return set(self._user_tokens.keys())

    async def find_user_by_token(self, access_token: str) -> Optional[str]:
        """Find user subject by access token (reverse lookup)."""
        return self._token_users.get(access_token)


def create_session_storage() -> SessionStorage:
    """Create appropriate session storage based on configuration."""
    redis_url = os.environ.get("REDIS_URL")

    if redis_url and REDIS_AVAILABLE:
        logger.info(f"Using Redis session storage: {redis_url.split('@')[-1] if '@' in redis_url else redis_url}")
        return RedisSessionStorage(redis_url)
    else:
        if redis_url and not REDIS_AVAILABLE:
            logger.warning("REDIS_URL provided but Redis not available - using in-memory storage")
        else:
            logger.info("No REDIS_URL configured - using in-memory storage")
        return InMemorySessionStorage()
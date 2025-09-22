"""In-memory session storage for development and testing."""

from datetime import datetime, timedelta
from typing import Optional, Set
import logging

from .base import SessionStorage

logger = logging.getLogger("synapse_mcp.session_storage")


class InMemorySessionStorage(SessionStorage):
    """Fallback in-memory user-subject-based storage for development."""

    def __init__(self) -> None:
        self._user_tokens: dict[str, str] = {}
        self._token_users: dict[str, str] = {}
        self._token_metadata: dict[str, dict[str, str]] = {}

    async def set_user_token(self, user_subject: str, access_token: str, ttl_seconds: int = 3600) -> None:
        metadata = {
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(seconds=ttl_seconds)).isoformat(),
            "user_subject": user_subject,
        }

        old_token = self._user_tokens.get(user_subject)
        if old_token:
            self._token_users.pop(old_token, None)
            self._token_metadata.pop(old_token, None)

        self._user_tokens[user_subject] = access_token
        self._token_users[access_token] = user_subject
        self._token_metadata[access_token] = metadata

        logger.debug("Stored user %s -> token %s*** in memory", user_subject, access_token[:20])

    async def get_user_token(self, user_subject: str) -> Optional[str]:
        return self._user_tokens.get(user_subject)

    async def remove_user_token(self, user_subject: str) -> None:
        access_token = self._user_tokens.pop(user_subject, None)
        if access_token:
            self._token_users.pop(access_token, None)
            self._token_metadata.pop(access_token, None)
            logger.debug("Removed user %s from memory", user_subject)

    async def cleanup_expired_tokens(self) -> None:
        current_time = datetime.utcnow()
        expired_tokens = []

        for access_token, metadata in list(self._token_metadata.items()):
            try:
                expires_at = datetime.fromisoformat(metadata["expires_at"])
                if expires_at < current_time:
                    expired_tokens.append(access_token)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Error processing token metadata: %s", exc)
                expired_tokens.append(access_token)

        for access_token in expired_tokens:
            user_subject = self._token_users.get(access_token)
            if user_subject:
                await self.remove_user_token(user_subject)

        if expired_tokens:
            logger.info("Cleaned up %s expired tokens from memory", len(expired_tokens))

    async def get_all_user_subjects(self) -> Set[str]:
        return set(self._user_tokens.keys())

    async def find_user_by_token(self, access_token: str) -> Optional[str]:
        return self._token_users.get(access_token)


__all__ = ["InMemorySessionStorage"]

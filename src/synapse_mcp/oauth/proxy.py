"""FastMCP OAuth proxy extensions for Synapse."""

import logging
from typing import Optional

from fastmcp.server.auth import OAuthProxy

from ..session_storage import create_session_storage

logger = logging.getLogger("synapse_mcp.oauth")


class SessionAwareOAuthProxy(OAuthProxy):
    """OAuth proxy that mirrors tokens into session storage."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._session_storage = create_session_storage()

    async def _handle_idp_callback(self, request, *args, **kwargs):
        session_id = _extract_session_id(request)
        if session_id:
            logger.debug("OAuth callback processing for session: %s", session_id)

        result = await super()._handle_idp_callback(request, *args, **kwargs)
        if result:
            try:
                await self._map_new_tokens_to_users()
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Failed to map tokens to users: %s", exc)
        return result

    async def _map_new_tokens_to_users(self) -> None:
        existing_users = await self._session_storage.get_all_user_subjects()
        unmapped_tokens = [token for token in self._access_tokens if await self._session_storage.find_user_by_token(token) is None]

        for token_key in unmapped_tokens:
            try:
                import jwt

                decoded = jwt.decode(token_key, options={"verify_signature": False})
                user_subject = decoded.get("sub")
                if user_subject:
                    await self._session_storage.set_user_token(user_subject, token_key, ttl_seconds=3600)
                    logger.info("Mapped token %s*** to user %s", token_key[:20], user_subject)
                else:
                    logger.warning("Token %s*** has no subject claim", token_key[:20])
            except Exception as exc:  # pragma: no cover - decoding failures
                logger.warning("Failed to decode token %s***: %s", token_key[:20], exc)

    async def get_user_token(self, user_subject: str) -> Optional[str]:
        token_key = await self._session_storage.get_user_token(user_subject)
        if token_key and token_key in self._access_tokens:
            return token_key
        return None

    async def cleanup_user_tokens(self, user_subject: str) -> None:
        token_key = await self._session_storage.get_user_token(user_subject)
        if token_key:
            if token_key in self._access_tokens:
                del self._access_tokens[token_key]
            await self._session_storage.remove_user_token(user_subject)
            logger.info("Cleaned up token for user %s", user_subject)

    async def cleanup_expired_tokens(self) -> None:
        await self._session_storage.cleanup_expired_tokens()

        existing_users = await self._session_storage.get_all_user_subjects()
        mapped_tokens = {
            token
            for user_subject in existing_users
            for token in [await self._session_storage.get_user_token(user_subject)]
            if token
        }

        orphaned = [token for token in list(self._access_tokens.keys()) if token not in mapped_tokens]
        for token in orphaned:
            if self._is_token_old_enough_to_cleanup(token):
                del self._access_tokens[token]

        if orphaned:
            logger.info("Cleaned up %s orphaned tokens from OAuth proxy", len(orphaned))

    def _is_token_old_enough_to_cleanup(self, token: str, min_age_seconds: int = 30) -> bool:
        try:
            import jwt
            from datetime import datetime

            decoded = jwt.decode(token, options={"verify_signature": False})
            issued_at = decoded.get("iat")
            if not issued_at:
                return True
            token_age = datetime.utcnow().timestamp() - issued_at
            if token_age <= min_age_seconds:
                logger.debug("Token is only %.1fs old, keeping for now", token_age)
                return False
            return True
        except Exception as exc:  # pragma: no cover - decoding failures
            logger.debug("Error checking token age, assuming old enough: %s", exc)
            return True

    async def get_token_for_current_user(self) -> Optional[tuple[str, Optional[str]]]:
        """Return a token and subject when a single active user is known."""

        subjects = await self._session_storage.get_all_user_subjects()
        if len(subjects) != 1:
            return None

        subject = next(iter(subjects))
        token = await self._session_storage.get_user_token(subject)
        if not token:
            return None
        return token, subject


def _extract_session_id(request) -> Optional[str]:
    try:
        if hasattr(request, "headers"):
            session_id = request.headers.get("mcp-session-id")
            if session_id:
                return session_id
        if hasattr(request, "state"):
            session_context = getattr(request.state, "session_context", None)
            if session_context and hasattr(session_context, "session_id"):
                return session_context.session_id
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Could not extract session ID from callback: %s", exc)
    return None


__all__ = ["SessionAwareOAuthProxy"]

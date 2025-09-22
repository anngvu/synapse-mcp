"""FastMCP middleware that copies OAuth tokens into the request context."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any, Optional, Sequence

from fastmcp.server.middleware import Middleware, MiddlewareContext

logger = logging.getLogger("synapse_mcp.auth_middleware")


@dataclass
class TokenBundle:
    token: str
    scopes: Sequence[str]
    subject: Optional[str]


class OAuthTokenMiddleware(Middleware):
    """Ensure FastMCP call contexts expose the current OAuth token."""

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        await self._store_auth_info(context)
        return await call_next(context)

    async def on_call_resource(self, context: MiddlewareContext, call_next):
        await self._store_auth_info(context)
        return await call_next(context)

    async def _store_auth_info(self, context: MiddlewareContext) -> None:
        fast_ctx = getattr(context, "fastmcp_context", None)
        if fast_ctx is None:
            logger.debug("Skipping OAuth middleware: missing fastmcp_context")
            return

        bundle = await self._resolve_token_bundle(context, fast_ctx)
        if not bundle:
            logger.debug("No OAuth token available for this call")
            return

        if hasattr(fast_ctx, "set_state"):
            fast_ctx.set_state("oauth_access_token", bundle.token)
            fast_ctx.set_state("token_scopes", list(bundle.scopes))
            fast_ctx.set_state("user_subject", bundle.subject)
            logger.info("Stored OAuth token for subject: %s", bundle.subject)
        else:
            logger.warning("FastMCP context does not expose set_state; unable to cache token")

    async def _resolve_token_bundle(self, context: MiddlewareContext, fast_ctx: Any) -> Optional[TokenBundle]:
        header_bundle = _bundle_from_headers(context)
        if header_bundle:
            return header_bundle

        cached_bundle = _bundle_from_state(fast_ctx)
        if cached_bundle:
            return cached_bundle

        proxy_bundle = await _bundle_from_proxy(context, fast_ctx)
        if proxy_bundle:
            return proxy_bundle

        return None


def _bundle_from_headers(context: MiddlewareContext) -> Optional[TokenBundle]:
    message = getattr(context, "message", None)
    headers = getattr(message, "headers", {}) if message else {}
    auth_header = headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer "):]
        logger.debug("Using Authorization header bearer token")
        return TokenBundle(token=token, scopes=[], subject=None)
    return None


def _bundle_from_state(fast_ctx: Any) -> Optional[TokenBundle]:
    if not hasattr(fast_ctx, "get_state"):
        return None
    token = fast_ctx.get_state("oauth_access_token")
    if not token:
        return None
    scopes = fast_ctx.get_state("token_scopes", []) or []
    subject = fast_ctx.get_state("user_subject")
    logger.debug("Using cached OAuth token from context state")
    return TokenBundle(token=token, scopes=scopes, subject=subject)


async def _bundle_from_proxy(context: MiddlewareContext, fast_ctx: Any) -> Optional[TokenBundle]:
    server = getattr(fast_ctx, "fastmcp", None)
    auth_proxy = getattr(server, "auth", None) if server else None
    if not auth_proxy:
        return None

    subject = None
    token = None

    # Preferred path: dedicated helper on session-aware proxy
    if hasattr(auth_proxy, "get_token_for_current_user"):
        token_result = await auth_proxy.get_token_for_current_user()
        if token_result:
            token, subject = token_result

    # Fallback: if we know the subject already, reuse proxy's helper
    if token is None and hasattr(fast_ctx, "get_state"):
        subject = fast_ctx.get_state("user_subject")
        if subject and hasattr(auth_proxy, "get_user_token"):
            token = await auth_proxy.get_user_token(subject)

    if not token:
        return None

    scopes = []
    if hasattr(fast_ctx, "get_state"):
        scopes = fast_ctx.get_state("token_scopes", []) or []

    logger.debug("Resolved OAuth token via proxy for subject: %s", subject)
    return TokenBundle(token=token, scopes=scopes, subject=subject)


__all__ = ["OAuthTokenMiddleware"]

"""
FastMCP middleware to bridge OAuth authentication to connection context.

This middleware captures the verified OAuth access token from FastMCP's auth system
and stores it in the context state where our connection-scoped authentication
system can access it.
"""

import logging
from typing import Any
from fastmcp.server.middleware import Middleware, MiddlewareContext

logger = logging.getLogger("synapse_mcp.auth_middleware")


class OAuthTokenMiddleware(Middleware):
    """
    Middleware that captures OAuth tokens from FastMCP auth and stores them
    in the context state for connection-scoped authentication.
    """

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """
        Intercept tool EXECUTION to extract and store OAuth token information.

        Runs before each tool call and ensures that any
        verified OAuth token is available in the context state for execution.
        """
        logger.info(f"OAuth middleware on_call_tool called for tool: {context.message.name}")
        await self._store_auth_info(context)
        return await call_next(context)

    async def on_call_resource(self, context: MiddlewareContext, call_next):
        """
        Intercept resource EXECUTION to extract and store OAuth token information.

        Resources need authentication context when they're actually called.
        """
        await self._store_auth_info(context)
        return await call_next(context)

    async def _store_auth_info(self, context: MiddlewareContext):
        """
        Extract and store OAuth token information in context for execution operations.

        This is ONLY called for execution operations (call_tool, call_resource),
        not for list operations which should work without authentication.
        """
        try:
            logger.debug(f"_store_auth_info called with context: {type(context)}")
            logger.debug(f"Context has fastmcp_context: {hasattr(context, 'fastmcp_context')}")

            # Access the FastMCP context if available
            if hasattr(context, 'fastmcp_context') and context.fastmcp_context:
                fastmcp_ctx = context.fastmcp_context

                # Debug: examine the context structure
                logger.debug(f"FastMCP context type: {type(fastmcp_ctx)}")
                if hasattr(fastmcp_ctx, 'fastmcp'):
                    server = fastmcp_ctx.fastmcp
                    logger.debug(f"Server type: {type(server)}")
                    if hasattr(server, 'auth'):
                        logger.debug(f"Server has auth: {server.auth}")

                # Try to access authentication information from FastMCP
                auth_info = await self._extract_auth_info(context)

                if auth_info:
                    # Store authentication info in context state
                    if hasattr(fastmcp_ctx, 'set_state'):
                        fastmcp_ctx.set_state("oauth_access_token", auth_info.get("access_token"))
                        fastmcp_ctx.set_state("token_scopes", auth_info.get("scopes", []))
                        fastmcp_ctx.set_state("user_subject", auth_info.get("subject"))

                        logger.info(f"Stored OAuth token in context for subject: {auth_info.get('subject')}")
                    else:
                        logger.warning("FastMCP context doesn't support set_state")
                else:
                    logger.debug("No OAuth authentication info found in request")
            else:
                logger.debug("No FastMCP context available in middleware")

        except Exception as e:
            logger.error(f"Error in OAuth token middleware: {e}")
            # Don't fail the request if middleware has issues

    async def _extract_auth_info(self, context: MiddlewareContext) -> dict[str, Any] | None:
        """
        Extract authentication information from the middleware context.

        Tries various sources in order of priority to find the OAuth token.
        """
        try:
            # 1. Check Authorization header (most direct)
            if hasattr(context, 'message') and hasattr(context.message, 'headers'):
                auth_header = context.message.headers.get('Authorization')
                if auth_header and auth_header.startswith('Bearer '):
                    token = auth_header[7:]  # Remove 'Bearer ' prefix
                    logger.debug(f"Found Bearer token in headers: {token[:20]}...")
                    return {"access_token": token}

            # 2. Check FastMCP context state (previously stored) - HIGHEST PRIORITY
            if hasattr(context, 'fastmcp_context') and context.fastmcp_context:
                fastmcp_ctx = context.fastmcp_context
                if hasattr(fastmcp_ctx, 'get_state'):
                    existing_token = fastmcp_ctx.get_state("oauth_access_token")
                    if existing_token:
                        logger.debug("Found existing OAuth token in context state - using cached token")
                        return {"access_token": existing_token}

            # 3. Check FastMCP server auth proxy
            if (hasattr(context, 'fastmcp_context') and context.fastmcp_context and
                hasattr(context.fastmcp_context, 'fastmcp')):

                server = context.fastmcp_context.fastmcp
                if hasattr(server, 'auth') and server.auth:
                    auth_proxy = server.auth

                    # Try to load access token from OAuth proxy
                    try:
                        # Method 1: Try with client_id if available
                        client_id = getattr(context.fastmcp_context, 'client_id', None)
                        logger.debug(f"FastMCP context client_id: {client_id}")

                        if client_id and hasattr(auth_proxy, 'load_access_token'):
                            access_token = auth_proxy.load_access_token(client_id)
                            if access_token:
                                logger.debug(f"Loaded access token from OAuth proxy for client: {client_id}")
                                return {"access_token": access_token}

                        # Method 2: Try to get session-specific token
                        session_id = context.fastmcp_context.session_id if context.fastmcp_context else None
                        logger.debug(f"FastMCP context session_id: {session_id}")

                        if hasattr(auth_proxy, '_access_tokens') and auth_proxy._access_tokens:
                            logger.debug(f"OAuth proxy has {len(auth_proxy._access_tokens)} access tokens")
                            logger.debug(f"Available token keys: {[key[:20] + '***' for key in auth_proxy._access_tokens.keys()]}")

                            # Try to find session-specific token mapping FIRST (before cleanup)
                            session_token = self._get_session_token(auth_proxy, session_id, context.fastmcp_context)

                            if session_token:
                                logger.debug(f"Found session-specific token for session: {session_id}")
                                return {"access_token": session_token}

                            # Try to find a token by user subject (the primary method now)
                            if hasattr(auth_proxy, '_session_storage'):
                                # Find user subject from any available tokens and match with storage
                                user_subject = await self._find_current_user_subject(auth_proxy)
                                if user_subject:
                                    user_token = await auth_proxy._session_storage.get_user_token(user_subject)
                                    if user_token:
                                        logger.info(f"Found user token for subject {user_subject}")
                                        if hasattr(context.fastmcp_context, 'set_state'):
                                            context.fastmcp_context.set_state("oauth_access_token", user_token)
                                            context.fastmcp_context.set_state("user_subject", user_subject)
                                        return {"access_token": user_token}

                            # Legacy: Try using the session-aware OAuth proxy method (for backwards compatibility)
                            if hasattr(auth_proxy, 'get_user_token'):
                                # Try to get user subject from available tokens
                                user_subject = await self._find_current_user_subject(auth_proxy)
                                if user_subject:
                                    proxy_user_token = await auth_proxy.get_user_token(user_subject)
                                    if proxy_user_token:
                                        logger.debug(f"Found proxy user token for subject: {user_subject}")
                                        if hasattr(context.fastmcp_context, 'set_state'):
                                            context.fastmcp_context.set_state("oauth_access_token", proxy_user_token)
                                            context.fastmcp_context.set_state("user_subject", user_subject)
                                        return {"access_token": proxy_user_token}

                            # Fallback: if only one token exists after cleanup, it's likely the current session's
                            if len(auth_proxy._access_tokens) == 1:
                                token_key = next(iter(auth_proxy._access_tokens.keys()))
                                logger.debug(f"Using single remaining token for session: {session_id}")

                                # Map this token to the current session
                                self._map_token_to_session(token_key, session_id, context.fastmcp_context)

                                return {"access_token": token_key}
                            else:
                                logger.warning(f"Multiple tokens found ({len(auth_proxy._access_tokens)}) after cleanup, cannot safely determine which belongs to session: {session_id}")
                                # Force cleanup of all tokens to reset state
                                self._force_token_cleanup(auth_proxy)
                        else:
                            logger.debug("No _access_tokens found in OAuth proxy")

                    except Exception as e:
                        logger.debug(f"Error accessing OAuth proxy tokens: {e}")

                    # Fallback: check common token attributes
                    for attr in ['current_token', '_current_access_token', 'access_token', 'token']:
                        token_data = getattr(auth_proxy, attr, None)
                        if token_data:
                            logger.debug(f"Found token in server.auth.{attr}")
                            parsed = self._parse_auth_data(token_data)
                            if parsed:
                                return parsed

            # 4. Check context attributes for auth data
            for source, attr_list in [
                (getattr(context, 'request', None), ['auth', 'auth_context', 'access_token', 'token_info']),
                (getattr(context, 'fastmcp_context', None), ['auth_info', 'access_token', 'token_info', '_auth_context']),
                (context, ['auth_context'])
            ]:
                if source:
                    for attr in attr_list:
                        auth_data = getattr(source, attr, None)
                        if auth_data:
                            logger.debug(f"Found auth info in {attr}")
                            parsed = self._parse_auth_data(auth_data)
                            if parsed:
                                return parsed

        except Exception as e:
            logger.debug(f"Error extracting auth info: {e}")

        return None

    def _parse_auth_context(self, auth_context: Any) -> dict[str, Any] | None:
        """Parse authentication context object."""
        try:
            result = {}

            # Try common attribute names for tokens
            for token_attr in ['token', 'access_token', 'raw_token']:
                if hasattr(auth_context, token_attr):
                    result['access_token'] = getattr(auth_context, token_attr)
                    break

            # Try common attribute names for scopes
            for scope_attr in ['scopes', 'scope']:
                if hasattr(auth_context, scope_attr):
                    result['scopes'] = getattr(auth_context, scope_attr)
                    break

            # Try common attribute names for subject
            for subj_attr in ['sub', 'subject', 'user_id']:
                if hasattr(auth_context, subj_attr):
                    result['subject'] = getattr(auth_context, subj_attr)
                    break

            return result if result else None

        except Exception as e:
            logger.debug(f"Error parsing auth context: {e}")
            return None

    def _parse_auth_data(self, auth_data: Any) -> dict[str, Any] | None:
        """Parse various forms of authentication data."""
        try:
            # If it's a string, assume it's a token
            if isinstance(auth_data, str):
                return {"access_token": auth_data}

            # If it's a dict, look for token fields
            if isinstance(auth_data, dict):
                result = {}

                # Look for token
                for key in ['access_token', 'token', 'raw_token']:
                    if key in auth_data:
                        result['access_token'] = auth_data[key]
                        break

                # Look for scopes
                for key in ['scopes', 'scope']:
                    if key in auth_data:
                        result['scopes'] = auth_data[key]
                        break

                # Look for subject
                for key in ['sub', 'subject', 'user_id']:
                    if key in auth_data:
                        result['subject'] = auth_data[key]
                        break

                return result if result else None

            # If it's an object, try to parse it like auth context
            return self._parse_auth_context(auth_data)

        except Exception as e:
            logger.debug(f"Error parsing auth data: {e}")
            return None

    async def _find_current_user_subject(self, auth_proxy) -> str | None:
        """
        Find the user subject for the current request by examining available tokens.

        This is the key method for user-subject-based authentication that works
        across multiple transports and sessions.
        """
        try:
            if not hasattr(auth_proxy, '_access_tokens'):
                return None

            # Check each available token to find a valid user subject
            # In multi-user scenarios, we'll need to determine which user this request belongs to
            for token_key in auth_proxy._access_tokens:
                try:
                    # Decode the token to get user subject
                    import jwt
                    decoded = jwt.decode(token_key, options={"verify_signature": False})
                    user_subject = decoded.get('sub')

                    if user_subject:
                        # Verify the token is still valid and not expired
                        exp = decoded.get('exp')
                        if exp:
                            import time
                            if exp < time.time():
                                logger.debug(f"Token for subject {user_subject} has expired")
                                continue

                        logger.debug(f"Found valid user subject: {user_subject}")
                        # For now, return the first valid user subject found
                        # In future, this could be enhanced with request-specific user identification
                        return user_subject

                except Exception as e:
                    logger.debug(f"Error checking token for user subject: {e}")
                    continue

            return None

        except Exception as e:
            logger.error(f"Error finding current user subject: {e}")
            return None

    async def _find_token_by_user_match(self, auth_proxy, session_id: str) -> str | None:
        """
        Find a token for the same user from a different session.

        This handles the case where OAuth flow happens in one session
        but tool requests come from a different session for the same user.
        """
        try:
            if not hasattr(auth_proxy, '_access_tokens'):
                return None

            # Check each available token to see if any belong to the same user
            for token_key in auth_proxy._access_tokens:
                try:
                    # Decode the token to get user subject
                    import jwt
                    decoded = jwt.decode(token_key, options={"verify_signature": False})
                    token_subject = decoded.get('sub')

                    if token_subject:
                        logger.debug(f"Checking token with subject {token_subject} for session {session_id}")

                        # For now, since we can't easily match users across sessions,
                        # we'll use the most recent valid token if there are multiple users
                        # This is a simplified approach - in production you might want
                        # more sophisticated user matching

                        # Verify the token is still valid and not expired
                        exp = decoded.get('exp')
                        if exp:
                            import time
                            if exp < time.time():
                                logger.debug(f"Token for subject {token_subject} has expired")
                                continue

                        logger.debug(f"Found valid token for subject {token_subject}")
                        return token_key

                except Exception as e:
                    logger.debug(f"Error checking token for user match: {e}")
                    continue

            return None

        except Exception as e:
            logger.error(f"Error in user token matching: {e}")
            return None

    async def _cleanup_expired_tokens(self, auth_proxy):
        """Remove expired tokens from the OAuth proxy."""
        try:
            # If we have a session-aware proxy, use its cleanup method
            if hasattr(auth_proxy, 'cleanup_expired_tokens'):
                await auth_proxy.cleanup_expired_tokens()
                return

            # Fallback to basic cleanup for regular OAuth proxy
            if not hasattr(auth_proxy, '_access_tokens'):
                return

            current_tokens = dict(auth_proxy._access_tokens)
            expired_tokens = []

            for token_key, token_obj in current_tokens.items():
                try:
                    # Check if token has expiration info
                    if hasattr(token_obj, 'expires_at'):
                        import time
                        if token_obj.expires_at and token_obj.expires_at < time.time():
                            expired_tokens.append(token_key)
                            logger.debug(f"Token {token_key[:20]}*** has expired")
                    # Also check JWT expiration
                    elif hasattr(token_obj, 'token') or isinstance(token_obj, str):
                        token_str = token_obj.token if hasattr(token_obj, 'token') else token_obj
                        if self._is_jwt_expired(token_str):
                            expired_tokens.append(token_key)
                            logger.debug(f"JWT token {token_key[:20]}*** has expired")
                except Exception as e:
                    logger.debug(f"Error checking token expiration: {e}")

            # Remove expired tokens
            for token_key in expired_tokens:
                try:
                    del auth_proxy._access_tokens[token_key]
                    logger.info(f"Removed expired token {token_key[:20]}***")
                except Exception as e:
                    logger.warning(f"Failed to remove expired token: {e}")

            if expired_tokens:
                logger.info(f"Cleaned up {len(expired_tokens)} expired tokens")

        except Exception as e:
            logger.error(f"Error during token cleanup: {e}")

    def _is_jwt_expired(self, token: str) -> bool:
        """Check if a JWT token is expired."""
        try:
            import jwt
            import time

            # Decode without verification to check expiration
            decoded = jwt.decode(token, options={"verify_signature": False})
            exp = decoded.get('exp')

            if exp:
                return exp < time.time()
            return False
        except Exception:
            return False

    def _get_session_token(self, auth_proxy, session_id, fastmcp_context):
        """Get the token associated with a specific session."""
        try:
            if not session_id or not fastmcp_context:
                return None

            # Check if we have a session-to-token mapping stored in context
            if hasattr(fastmcp_context, 'get_state'):
                stored_token = fastmcp_context.get_state("oauth_access_token")
                if stored_token and stored_token in auth_proxy._access_tokens:
                    logger.debug(f"Found stored token for session {session_id}")
                    return stored_token

            # Check if we have a global session mapping (could be implemented later with Redis)
            # For now, we rely on context state storage

            return None
        except Exception as e:
            logger.debug(f"Error getting session token: {e}")
            return None

    def _map_token_to_session(self, token_key, session_id, fastmcp_context):
        """Map a token to a specific session."""
        try:
            if fastmcp_context and hasattr(fastmcp_context, 'set_state'):
                fastmcp_context.set_state("oauth_access_token", token_key)
                fastmcp_context.set_state("oauth_session_id", session_id)
                logger.debug(f"Mapped token to session {session_id}")
        except Exception as e:
            logger.warning(f"Failed to map token to session: {e}")

    def _force_token_cleanup(self, auth_proxy):
        """Force cleanup of all tokens to reset OAuth proxy state."""
        try:
            if hasattr(auth_proxy, '_access_tokens'):
                token_count = len(auth_proxy._access_tokens)
                auth_proxy._access_tokens.clear()
                logger.warning(f"Force-cleared {token_count} tokens due to session mapping issues")
        except Exception as e:
            logger.error(f"Error during force token cleanup: {e}")

# No handlers for list operations - they should work without authentication
    # on_list_tools, on_list_resources, on_list_prompts are intentionally omitted
    # These operations provide public capability discovery and don't need auth context
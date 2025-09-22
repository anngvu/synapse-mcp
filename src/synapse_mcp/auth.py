"""
FastMCP OAuth proxy configuration for Synapse authentication. 

"""

import os
import base64
import json
import logging
import asyncio
from typing import Optional, Dict, Any, List
from fastmcp.server.auth import OAuthProxy
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from jwt import PyJWKClient, decode
from jwt.exceptions import PyJWTError
from .session_storage import create_session_storage

logger = logging.getLogger("synapse_mcp.auth")


class SessionAwareOAuthProxy(OAuthProxy):
    """Extended OAuth proxy that tracks session-to-token mappings using Redis."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Use Redis-backed session storage for scalability
        self._session_storage = create_session_storage()

    async def _handle_idp_callback(self, request, *args, **kwargs):
        """Override callback handling to capture session context."""
        # Get the session ID from the request context if available
        session_id = None
        try:
            # Try to extract session ID from request headers or context
            if hasattr(request, 'headers'):
                session_id = request.headers.get("mcp-session-id")

            # Try to get from request state/context
            if not session_id and hasattr(request, 'state'):
                session_context = getattr(request.state, 'session_context', None)
                if session_context and hasattr(session_context, 'session_id'):
                    session_id = session_context.session_id

            logger.debug(f"OAuth callback processing for session: {session_id}")
        except Exception as e:
            logger.debug(f"Could not extract session ID from callback: {e}")

        # Call the parent implementation
        result = await super()._handle_idp_callback(request, *args, **kwargs)

        # After successful callback, map any new tokens to user subjects
        if result:
            try:
                await self._map_new_tokens_to_users()
            except Exception as e:
                logger.warning(f"Failed to map tokens to users: {e}")

        return result

    async def _map_new_tokens_to_users(self):
        """Map any newly created tokens to their user subjects."""
        try:
            # Get all existing user subjects to find unmapped tokens
            existing_users = await self._session_storage.get_all_user_subjects()

            # Find tokens that aren't mapped to any user yet
            unmapped_tokens = []
            for token_key in self._access_tokens:
                # Check if this token is already mapped to any user
                existing_user = await self._session_storage.find_user_by_token(token_key)
                if not existing_user:
                    unmapped_tokens.append(token_key)

            # Map unmapped tokens to their user subjects by decoding the JWT
            for token_key in unmapped_tokens:
                try:
                    import jwt
                    # Decode token to get user subject
                    decoded = jwt.decode(token_key, options={"verify_signature": False})
                    user_subject = decoded.get('sub')

                    if user_subject:
                        # Store the mapping with 1-hour TTL (can be configured)
                        await self._session_storage.set_user_token(user_subject, token_key, ttl_seconds=3600)
                        logger.info(f"Mapped token {token_key[:20]}*** to user {user_subject}")
                    else:
                        logger.warning(f"Token {token_key[:20]}*** has no subject claim")

                except Exception as e:
                    logger.warning(f"Failed to decode token {token_key[:20]}***: {e}")

        except Exception as e:
            logger.error(f"Error mapping tokens to users: {e}")

    async def get_user_token(self, user_subject: str) -> str | None:
        """Get the access token for a specific user subject."""
        try:
            token_key = await self._session_storage.get_user_token(user_subject)
            if token_key and token_key in self._access_tokens:
                return token_key
            return None
        except Exception as e:
            logger.error(f"Error getting user token: {e}")
            return None

    async def cleanup_user_tokens(self, user_subject: str):
        """Clean up tokens for a specific user."""
        try:
            token_key = await self._session_storage.get_user_token(user_subject)
            if token_key:
                # Remove from OAuth proxy
                if token_key in self._access_tokens:
                    del self._access_tokens[token_key]

                # Remove from session storage
                await self._session_storage.remove_user_token(user_subject)

                logger.info(f"Cleaned up token for user {user_subject}")
        except Exception as e:
            logger.error(f"Error cleaning up user tokens: {e}")

    async def cleanup_expired_tokens(self):
        """Clean up expired tokens from both OAuth proxy and session storage."""
        try:
            # Clean up from session storage first
            await self._session_storage.cleanup_expired_tokens()

            # Then clean up orphaned tokens from OAuth proxy
            existing_users = await self._session_storage.get_all_user_subjects()
            mapped_tokens = set()

            for user_subject in existing_users:
                token = await self._session_storage.get_user_token(user_subject)
                if token:
                    mapped_tokens.add(token)

            # Remove unmapped tokens from OAuth proxy, but only if they're old enough
            # This prevents removing tokens that were just created but not yet mapped
            oauth_tokens = set(self._access_tokens.keys())
            unmapped_tokens = oauth_tokens - mapped_tokens

            truly_orphaned = []
            for token in unmapped_tokens:
                # Check if this is a fresh token (might not be mapped yet)
                if self._is_token_old_enough_to_cleanup(token):
                    truly_orphaned.append(token)
                else:
                    logger.debug(f"Skipping cleanup of recent unmapped token {token[:20]}***")

            for token in truly_orphaned:
                if token in self._access_tokens:
                    del self._access_tokens[token]

            if truly_orphaned:
                logger.info(f"Cleaned up {len(truly_orphaned)} truly orphaned tokens from OAuth proxy")

        except Exception as e:
            logger.error(f"Error during expired token cleanup: {e}")

    def _is_token_old_enough_to_cleanup(self, token: str, min_age_seconds: int = 30) -> bool:
        """
        Check if a token is old enough to be considered truly orphaned.

        This prevents removing tokens that were just created during OAuth flow
        but haven't been mapped to a session yet.
        """
        try:
            import jwt
            from datetime import datetime, timedelta

            # Decode token to get creation time (iat claim)
            decoded = jwt.decode(token, options={"verify_signature": False})
            iat = decoded.get('iat')

            if not iat:
                # If no iat claim, assume it's old enough
                return True

            token_age = datetime.utcnow().timestamp() - iat
            is_old_enough = token_age > min_age_seconds

            if not is_old_enough:
                logger.debug(f"Token is only {token_age:.1f}s old, keeping for now")

            return is_old_enough

        except Exception as e:
            logger.debug(f"Error checking token age, assuming old enough: {e}")
            # If we can't determine age, err on the side of caution
            return True



class SynapseJWTVerifier:
    """Custom JWT verifier for Synapse tokens that returns FastMCP-compatible results; 
    FastMCP's JWTVerifier could not be used due to slight differences in Synapse tokens."""

    def __init__(self, jwks_uri: str, issuer: str, audience: str, 
                 algorithm: str = "RS256", required_scopes: Optional[List[str]] = None):
        """
        Initialize the verifier with Synapse-specific configuration.
        
        Args:
            jwks_uri: Synapse JWKS endpoint for key retrieval
            issuer: Expected token issuer (Synapse auth server)
            audience: Expected audience (OAuth client ID)
            algorithm: JWT signing algorithm (Synapse uses RS256)
            required_scopes: Minimum scopes required for access
        """
        self.issuer = issuer
        self.audience = audience
        self.algorithm = algorithm
        self.required_scopes = required_scopes or []
        self.jwks_client = PyJWKClient(uri=jwks_uri)
        
        # Thread pool for running sync JWT operations in async context
        self._executor = ThreadPoolExecutor(max_workers=2)

    async def verify_token(self, token: str) -> Optional[SimpleNamespace]:
        """
        Verify Synapse JWT token and return FastMCP-compatible access token info.
        
        Method needs to be async because:
        1. FastMCP framework expects async token verification
        2. We may need to make HTTP calls for JWKS refresh
        3. Synapse client authentication should be non-blocking
        
        Returns:
            SimpleNamespace object compatible with FastMCP's expected access token format,
            or None if verification fails
        """
        try:
            # Run the synchronous JWT verification in a thread pool
            # PyJWKClient is synchronous but need async for FastMCP integration
            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, self._verify_token_sync, token
            )
            return result

        except Exception as e:
            logger.error(f"Error in async Synapse JWT verification: {e}")
            return None

    def _verify_token_sync(self, token: str) -> Optional[SimpleNamespace]:
        """
        Synchronous JWT verification using robust PyJWKClient approach.
        """
        try:
            logger.info("Starting Synapse JWT verification using PyJWKClient")
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            
            decoded = decode(
                jwt=token,
                key=signing_key.key,
                algorithms=[signing_key.algorithm_name],
                audience=self.audience,
                issuer=self.issuer,
                options={"verify_aud": True}
            )

            logger.info(f"JWT successfully decoded. Subject: {decoded.get('sub')}")

            # Synapse stores scopes in a nested structure: token.access.scope
            # This is different from standard OAuth where scopes are at the root level
            scopes = self._extract_synapse_scopes(decoded)
            logger.info(f"Extracted scopes: {scopes}")

            # Validate required scopes for this resource server
            if not self._validate_required_scopes(scopes):
                logger.warning(f"Token lacks required scopes: {self.required_scopes}")
                return None

            # Token will be stored in context state by middleware for per-connection authentication

            # Return FastMCP-compatible access token object
            # FastMCP expects a specific object structure with these attributes
            access_token_obj = self._create_fastmcp_access_token(decoded, scopes, token)

            # Store the raw token for connection-scoped authentication
            # This will be available to the connection context
            access_token_obj.raw_token = token

            return access_token_obj

        except PyJWTError as e:
            logger.error(f"JWT verification failed: {e}")
            return None

    def _extract_synapse_scopes(self, decoded: Dict[str, Any]) -> List[str]:
        """
        Extract scopes from Synapse's nested token structure.
        
        Synapse tokens store scopes in decoded['access']['scope'] rather than
        the standard decoded['scope'] location. This is Synapse-specific.
        """
        scopes = []
        
        # Try Synapse's nested structure first
        if 'access' in decoded and 'scope' in decoded['access']:
            scopes = decoded['access']['scope']
            logger.debug(f"Found scopes in Synapse nested structure: {scopes}")
        # Fallback to standard OAuth scope location
        elif 'scope' in decoded:
            scope_str = decoded['scope']
            scopes = scope_str.split(' ') if isinstance(scope_str, str) else scope_str
            logger.debug(f"Found scopes in standard location: {scopes}")
        
        return scopes if isinstance(scopes, list) else []

    def _validate_required_scopes(self, token_scopes: List[str]) -> bool:
        """
        Validate that the token contains all required scopes for our resource server (this MCP server)
        """
        if not self.required_scopes:
            return True
            
        token_scope_set = set(token_scopes)
        required_scope_set = set(self.required_scopes)
        
        has_required = required_scope_set.issubset(token_scope_set)
        if not has_required:
            missing = required_scope_set - token_scope_set
            logger.warning(f"Missing required scopes: {missing}")
            
        return has_required


    def _create_fastmcp_access_token(self, decoded: Dict[str, Any], 
                                   scopes: List[str], token: str) -> SimpleNamespace:
        """
        Create a FastMCP-compatible access token object.
        
        FastMCP expects an object with specific attributes. We use SimpleNamespace
        to create a lightweight object that mimics the expected structure.
        
        This custom format is necessary because:
        1. FastMCP has specific expectations about access token object structure
        2. We need to bridge between PyJWT's dict output and FastMCP's object expectations
        3. We want to include Synapse-specific information (like nested scopes)
        """
        access_token = SimpleNamespace()
        
        # Standard OAuth/OIDC claims
        access_token.sub = decoded.get("sub")  # Subject (user ID)
        access_token.client_id = decoded.get("aud")  # Audience (OAuth client ID)
        access_token.expires_at = decoded.get("exp", 0)  # Expiration timestamp
        
        # Scope information (enhanced for Synapse)
        access_token.scopes = scopes
        
        # Full token information
        access_token.claims = decoded  # All JWT claims for advanced use
        access_token.token = token  # Raw token for API calls
        
        logger.debug(f"Created FastMCP access token for subject: {access_token.sub}")
        return access_token

    def __del__(self):
        """Clean up thread pool executor."""
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=False)

def create_oauth_proxy():
    """Create OAuth proxy for Synapse authentication."""
    # Check if PAT is available - if so, skip OAuth setup
    synapse_pat = os.environ.get("SYNAPSE_PAT")
    if synapse_pat:
        print("SYNAPSE_PAT detected - skipping OAuth configuration")
        return None

    # Get OAuth configuration from environment
    client_id = os.environ.get("SYNAPSE_OAUTH_CLIENT_ID")
    client_secret = os.environ.get("SYNAPSE_OAUTH_CLIENT_SECRET")
    redirect_uri = os.environ.get("SYNAPSE_OAUTH_REDIRECT_URI")
    server_url = os.environ.get("MCP_SERVER_URL", "http://127.0.0.1:9000")

    # For streamable-http transport, OAuth endpoints are at root level
    # Remove /mcp suffix if present to ensure OAuth endpoints work
    if server_url.endswith("/mcp"):
        server_url = server_url[:-4]

    # Normalize localhost vs 127.0.0.1 to prevent OAuth redirect mismatches
    if "localhost" in server_url:
        server_url = server_url.replace("localhost", "127.0.0.1")
        logger.info(f"Normalized server URL from localhost to 127.0.0.1: {server_url}")

    # If redirect_uri is not set, auto-generate it from server_url
    if not redirect_uri:
        redirect_uri = f"{server_url}/oauth/callback"
        logger.info(f"Auto-generated redirect URI: {redirect_uri}")
    # Normalize redirect_uri as well
    elif "localhost" in redirect_uri:
        redirect_uri = redirect_uri.replace("localhost", "127.0.0.1")
        logger.info(f"Normalized redirect URI from localhost to 127.0.0.1: {redirect_uri}")

    if not all([client_id, client_secret, redirect_uri]):
        print("OAuth configuration missing - running without authentication")
        return None

    # Configure custom JWT verifier for Synapse access tokens
    jwt_verifier = SynapseJWTVerifier(
        jwks_uri="https://repo-prod.prod.sagebase.org/auth/v1/oauth2/jwks",
        issuer="https://repo-prod.prod.sagebase.org/auth/v1",
        audience=client_id,
        algorithm="RS256",
        required_scopes=["view", "download", "modify"]
    )

    # FastMCP default is /auth/callback, but need /oauth/callback to match the original Synapse OAuth client registration
    redirect_path = "/oauth/callback"

    # Create OAuth proxy pointing to Synapse OAuth endpoints
    # Available scopes: https://rest-docs.synapse.org/rest/org/sagebionetworks/repo/model/oauth/OAuthScope.html
    # - openid: Required scope for OpenID Connect
    # - email: Returns email claims when used with 'openid'
    # - profile: Returns user profile information when used with 'openid'
    # - ga4gh_passport_v1: Returns GA4GH Passport when used with 'openid'
    # - view: Read object metadata
    # - download: Download data
    # - modify: Create or change content
    # - authorize: Authorize access and share resources
    # - offline_access: Access resources when user is not logged in
    auth = SessionAwareOAuthProxy(
        upstream_authorization_endpoint="https://signin.synapse.org",
        upstream_token_endpoint="https://repo-prod.prod.sagebase.org/auth/v1/oauth2/token",
        upstream_client_id=client_id,
        upstream_client_secret=client_secret,
        redirect_path=redirect_path,
        token_verifier=jwt_verifier,
        base_url=server_url
    )

    return auth
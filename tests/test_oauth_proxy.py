"""Tests for the session-aware OAuth proxy."""

from types import SimpleNamespace
import sys

import pytest

from synapse_mcp.oauth.proxy import SessionAwareOAuthProxy


pytestmark = pytest.mark.anyio("asyncio")


@pytest.fixture
def anyio_backend():
    return "asyncio"


class FakeStorage:
    def __init__(self):
        self.tokens = {}
        self.set_calls = []
        self.removed = []

    async def get_all_user_subjects(self):
        return set(self.tokens.keys())

    async def find_user_by_token(self, token):
        for subject, stored in self.tokens.items():
            if stored == token:
                return subject
        return None

    async def set_user_token(self, user_subject, access_token, ttl_seconds=3600):
        self.tokens[user_subject] = access_token
        self.set_calls.append((user_subject, access_token))

    async def get_user_token(self, user_subject):
        return self.tokens.get(user_subject)

    async def remove_user_token(self, user_subject):
        self.tokens.pop(user_subject, None)
        self.removed.append(user_subject)

    async def cleanup_expired_tokens(self):
        return None


def build_proxy(monkeypatch, storage):
    monkeypatch.setattr("synapse_mcp.oauth.proxy.create_session_storage", lambda: storage)
    return SessionAwareOAuthProxy(
        upstream_authorization_endpoint="https://auth",
        upstream_token_endpoint="https://token",
        upstream_client_id="client",
        upstream_client_secret="secret",
        redirect_path="/oauth/callback",
        token_verifier=SimpleNamespace(required_scopes=[]),
        base_url="http://localhost",
    )


@pytest.mark.anyio
async def test_map_new_tokens_populates_storage(monkeypatch):
    storage = FakeStorage()
    proxy = build_proxy(monkeypatch, storage)
    proxy._access_tokens = {"token123": object()}

    dummy_jwt = SimpleNamespace(decode=lambda token, options=None: {"sub": "user-1"})
    monkeypatch.setitem(sys.modules, "jwt", dummy_jwt)

    await proxy._map_new_tokens_to_users()

    assert storage.tokens["user-1"] == "token123"


@pytest.mark.anyio
async def test_get_token_for_current_user(monkeypatch):
    storage = FakeStorage()
    storage.tokens["user-1"] = "token123"
    proxy = build_proxy(monkeypatch, storage)

    result = await proxy.get_token_for_current_user()
    assert result == ("token123", "user-1")


@pytest.mark.anyio
async def test_cleanup_expired_tokens_removes_orphans(monkeypatch):
    storage = FakeStorage()
    storage.tokens["user-1"] = "token123"
    proxy = build_proxy(monkeypatch, storage)

    proxy._access_tokens = {"token123": object(), "token999": object()}
    monkeypatch.setattr(SessionAwareOAuthProxy, "_is_token_old_enough_to_cleanup", lambda self, token: True)

    await proxy.cleanup_expired_tokens()

    assert "token999" not in proxy._access_tokens
    assert "token123" in proxy._access_tokens

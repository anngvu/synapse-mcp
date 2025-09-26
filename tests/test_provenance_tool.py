from types import SimpleNamespace

import pytest

import synapse_mcp
import synapse_mcp.tools as tools
from synapse_mcp.context_helpers import ConnectionAuthError
from synapseclient.core.exceptions import SynapseHTTPError


class DummyContext:
    pass


def test_get_entity_provenance_returns_activity(monkeypatch):
    ctx = DummyContext()

    class DummyOps:
        def __init__(self):
            self.calls = []

        def get_entity_provenance(self, entity_id, version=None):
            self.calls.append((entity_id, version))
            return {"entityId": entity_id, "name": "Workflow"}

    dummy_ops = DummyOps()
    monkeypatch.setattr(tools, "get_entity_operations", lambda _: {"base": dummy_ops})

    result = synapse_mcp.get_entity_provenance.fn("syn123", ctx, version=3)

    assert result["entityId"] == "syn123"
    assert result["version"] == 3
    assert dummy_ops.calls == [("syn123", 3)]


def test_get_entity_provenance_invalid_id(monkeypatch):
    ctx = DummyContext()
    called = False

    def fail_ops(_):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(tools, "get_entity_operations", fail_ops)

    result = synapse_mcp.get_entity_provenance.fn("foo", ctx)

    assert "Invalid Synapse ID" in result["error"]
    assert not called


def test_get_entity_provenance_invalid_version(monkeypatch):
    ctx = DummyContext()
    monkeypatch.setattr(tools, "get_entity_operations", lambda _: pytest.fail("should not call ops"))

    result = synapse_mcp.get_entity_provenance.fn("syn123", ctx, version="not-a-number")

    assert result["entity_id"] == "syn123"
    assert "Invalid version" in result["error"]


def test_get_entity_provenance_requires_auth(monkeypatch):
    ctx = DummyContext()

    def fake_ops(_):
        raise ConnectionAuthError("missing token")

    monkeypatch.setattr(tools, "get_entity_operations", fake_ops)

    result = synapse_mcp.get_entity_provenance.fn("syn123", ctx)

    assert "Authentication required" in result["error"]
    assert result["entity_id"] == "syn123"


def test_get_entity_provenance_missing_record(monkeypatch):
    ctx = DummyContext()

    class DummyOps:
        def get_entity_provenance(self, entity_id, version=None):
            error = SynapseHTTPError("Not Found")
            error.response = SimpleNamespace(status_code=404)
            raise error

    monkeypatch.setattr(tools, "get_entity_operations", lambda _: {"base": DummyOps()})

    result = synapse_mcp.get_entity_provenance.fn("syn123", ctx)

    assert result["status_code"] == 404
    assert "No provenance records found" in result["error"]
    assert result["entity_id"] == "syn123"

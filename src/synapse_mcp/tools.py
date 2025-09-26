"""Tool registrations for Synapse MCP."""

import json
from typing import Any, Callable, Dict, List, Optional

from fastmcp import Context
from synapseclient.core.exceptions import SynapseHTTPError

from .app import mcp
from .connection_auth import get_synapse_client
from .context_helpers import ConnectionAuthError, get_entity_operations
from .utils import format_annotations, validate_synapse_id


DEFAULT_RETURN_FIELDS: List[str] = ["name", "description", "node_type"]


def _normalize_fields(fields: Optional[List[str]]) -> List[str]:
    """Deduplicate and strip return field entries while preserving order."""
    if not fields:
        return []

    seen: set[str] = set()
    normalized: List[str] = []
    for raw in fields:
        cleaned = str(raw).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        normalized.append(cleaned)
    return normalized


def _entity_error(
    message: str,
    *,
    entity_id: Optional[str] = None,
    version: Optional[int] = None,
    status_code: Optional[int] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"error": message}
    if entity_id:
        payload["entity_id"] = entity_id
    if version is not None:
        payload["version"] = version
    if status_code is not None:
        payload["status_code"] = status_code
    return payload


def _execute_entity_operation(
    entity_id: str,
    ctx: Context,
    operation: Callable[[Dict[str, Any]], Any],
    *,
    version: Optional[int] = None,
    on_exception: Optional[Callable[[Exception], Optional[Dict[str, Any]]]] = None,
) -> Any:
    if not validate_synapse_id(entity_id):
        return {"error": f"Invalid Synapse ID: {entity_id}"}

    try:
        entity_ops = get_entity_operations(ctx)
    except ConnectionAuthError as exc:
        return _entity_error(f"Authentication required: {exc}", entity_id=entity_id, version=version)

    try:
        return operation(entity_ops)
    except ConnectionAuthError as exc:
        return _entity_error(f"Authentication required: {exc}", entity_id=entity_id, version=version)
    except Exception as exc:  # pragma: no cover - defensive path
        if on_exception:
            handled = on_exception(exc)
            if handled is not None:
                return handled
        return _entity_error(str(exc), entity_id=entity_id, version=version)


@mcp.tool(
    title="Fetch Entity",
    description="Return Synapse entity metadata by ID (projects, folders, files, tables, etc.).",
    annotations={
        "readOnlyHint": True,
        "idempotentHint": True,
        "destructiveHint": False,
        "openWorldHint": True,
    },
)
def get_entity(entity_id: str, ctx: Context) -> Dict[str, Any]:
    """Return Synapse entity metadata by ID (projects, folders, files, tables, etc.)."""

    return _execute_entity_operation(
        entity_id,
        ctx,
        lambda ops: ops["base"].get_entity_by_id(entity_id),
    )


@mcp.tool(
    title="Fetch Entity Annotations",
    description="Return custom annotation key/value pairs for a Synapse entity.",
    annotations={
        "readOnlyHint": True,
        "idempotentHint": True,
        "destructiveHint": False,
        "openWorldHint": True,
    },
)
def get_entity_annotations(entity_id: str, ctx: Context) -> Dict[str, Any]:
    """Return custom annotation key/value pairs for a Synapse entity."""

    return _execute_entity_operation(
        entity_id,
        ctx,
        lambda ops: format_annotations(ops["base"].get_entity_annotations(entity_id)),
    )


@mcp.tool(
    title="Fetch Entity Provenance",
    description="Return provenance activity for a Synapse entity, if available.",
    annotations={
        "readOnlyHint": True,
        "idempotentHint": True,
        "destructiveHint": False,
        "openWorldHint": True,
    },
)
def get_entity_provenance(entity_id: str, ctx: Context, version: Optional[int] = None) -> Dict[str, Any]:
    """Return provenance activity for a Synapse entity."""
    if not validate_synapse_id(entity_id):
        return {"error": f"Invalid Synapse ID: {entity_id}"}

    version_arg: Optional[int] = None
    if version is not None:
        try:
            version_arg = int(version)
        except (TypeError, ValueError):
            return _entity_error(f"Invalid version: {version}", entity_id=entity_id)
        if version_arg < 1:
            return _entity_error(f"Invalid version: {version_arg}", entity_id=entity_id)

    def handle_exception(exc: Exception) -> Optional[Dict[str, Any]]:
        if isinstance(exc, SynapseHTTPError):
            response = getattr(exc, "response", None)
            status_code = getattr(response, "status_code", None) or getattr(exc, "status_code", None)
            message = str(exc)
            if status_code == 404:
                message = f"No provenance records found for entity {entity_id}"
            return _entity_error(
                message,
                entity_id=entity_id,
                version=version_arg,
                status_code=status_code,
            )
        return None

    def fetch(entity_ops: Dict[str, Any]) -> Dict[str, Any]:
        provenance = entity_ops["base"].get_entity_provenance(entity_id, version=version_arg)
        if version_arg is not None:
            provenance.setdefault("version", version_arg)
        return provenance

    return _execute_entity_operation(
        entity_id,
        ctx,
        fetch,
        version=version_arg,
        on_exception=handle_exception,
    )


@mcp.tool(
    title="List Entity Children",
    description="List children for Synapse container entities (projects or folders).",
    annotations={
        "readOnlyHint": True,
        "idempotentHint": True,
        "destructiveHint": False,
        "openWorldHint": True,
    },
)
def get_entity_children(entity_id: str, ctx: Context) -> List[Dict[str, Any]]:
    """List children for Synapse container entities (projects or folders)."""
    if not validate_synapse_id(entity_id):
        return [{"error": f"Invalid Synapse ID: {entity_id}"}]

    try:
        entity_ops = get_entity_operations(ctx)
        entity = entity_ops["base"].get_entity_by_id(entity_id)
        entity_type = entity.get("type", "").lower()

        if entity_type == "project":
            return entity_ops["project"].get_project_children(entity_id)
        if entity_type == "folder":
            return entity_ops["folder"].get_folder_children(entity_id)
        return [{"error": f"Entity {entity_id} is not a container entity"}]
    except ConnectionAuthError as exc:
        return [{"error": f"Authentication required: {exc}", "entity_id": entity_id}]
    except Exception as exc:  # pragma: no cover - defensive path
        return [{"error": str(exc), "entity_id": entity_id}]

@mcp.tool(
    title="Search Synapse",
    description=(
        "Search Synapse entities using keyword queries with optional name/type/parent filters. "
        "Results are served by Synapse as data custodian. Attribution and licensing are "
        "determined by the original contributors; check the specific entity's annotations or Wiki for details."
    ),
    annotations={
        "readOnlyHint": True,
        "idempotentHint": True,
        "destructiveHint": False,
        "openWorldHint": True,
    },
)
def search_synapse(
    ctx: Context,
    query_term: Optional[str] = None,
    name: Optional[str] = None,
    entity_type: Optional[str] = None,
    entity_types: Optional[List[str]] = None,
    parent_id: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
) -> Dict[str, Any]:
    """Search Synapse entities using keyword queries with optional name/type/parent filters.

    Results are served by Synapse as data custodian. Attribution and licensing are
    determined by the original contributors; review the returned entity metadata for
    details."""
    try:
        synapse_client = get_synapse_client(ctx)
    except ConnectionAuthError as exc:
        return {"error": f"Authentication required: {exc}"}

    sanitized_limit = max(0, min(limit, 100))
    sanitized_offset = max(0, offset)

    query_terms: List[str] = []
    if query_term:
        query_terms.append(query_term)
    if name and name not in query_terms:
        query_terms.append(name)

    default_return_fields = _normalize_fields(DEFAULT_RETURN_FIELDS)
    request_payload: Dict[str, Any] = {
        "queryTerm": query_terms,
        "start": sanitized_offset,
        "size": sanitized_limit,
    }

    normalized_fields = default_return_fields
    if normalized_fields:
        request_payload["returnFields"] = normalized_fields

    requested_types: List[str] = []
    if entity_types:
        requested_types.extend(entity_types)
    if entity_type:
        requested_types.append(entity_type)

    boolean_query: List[Dict[str, Any]] = []
    for item in requested_types:
        normalized = (item or "").strip().lower()
        if not normalized:
            continue
        boolean_query.append({"key": "node_type", "value": normalized})

    if parent_id:
        boolean_query.append({"key": "path", "value": parent_id})

    if boolean_query:
        request_payload["booleanQuery"] = boolean_query

    warnings: List[str] = []
    original_payload: Optional[Dict[str, Any]] = None
    dropped_return_fields: Optional[List[str]] = None

    try:
        response = synapse_client.restPOST("/search", body=json.dumps(request_payload))
    except ConnectionAuthError as exc:
        return {"error": f"Authentication required: {exc}"}
    except Exception as exc:  # pragma: no cover - defensive path
        error_message = str(exc)
        if "Invalid field name" in error_message and "returnFields" in request_payload:
            original_payload = dict(request_payload)
            dropped_return_fields = list(request_payload.get("returnFields", []))
            fallback_payload = {k: v for k, v in request_payload.items() if k != "returnFields"}

            try:
                response = synapse_client.restPOST("/search", body=json.dumps(fallback_payload))
            except Exception as fallback_exc:  # pragma: no cover - defensive path
                return {
                    "error": str(fallback_exc),
                    "query": fallback_payload,
                    "original_query": original_payload,
                    "dropped_return_fields": dropped_return_fields,
                }

            warnings.append(
                f"Synapse rejected requested return fields {dropped_return_fields}; retried without custom return fields."
            )
            request_payload = fallback_payload
        else:
            return {"error": error_message, "query": request_payload}

    result: Dict[str, Any] = {
        "found": response.get("found", 0),
        "start": response.get("start", sanitized_offset),
        "hits": response.get("hits", []),
        "facets": response.get("facets", []),
        "query": request_payload,
    }

    if warnings:
        result["warnings"] = warnings
    if original_payload:
        result["original_query"] = original_payload
    if dropped_return_fields:
        result["dropped_return_fields"] = dropped_return_fields

    return result


__all__ = [
    "get_entity",
    "get_entity_annotations",
    "get_entity_provenance",
    "get_entity_children",
    "search_synapse",
]

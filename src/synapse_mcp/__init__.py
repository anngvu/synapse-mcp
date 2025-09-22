from fastmcp import FastMCP, Context
from fastmcp.server.context import request_ctx
from typing import Dict, List, Any, Optional, Union
import synapseclient
import os
from datetime import datetime
from starlette.requests import Request
from starlette.responses import JSONResponse
from .entities import (
    BaseEntityOperations,
    ProjectOperations,
    FolderOperations,
    FileOperations,
    TableOperations,
    DatasetOperations,
)
from .query import QueryBuilder
from .utils import validate_synapse_id, format_annotations
from .entities.croissant import convert_to_croissant
from .connection_auth import get_synapse_client, ConnectionAuthError

# Create an MCP server with OAuth authentication
from .auth import create_oauth_proxy
from .auth_middleware import OAuthTokenMiddleware

auth = create_oauth_proxy()
mcp = FastMCP("Synapse MCP Server", auth=auth)

# Register OAuth token middleware to bridge auth to connection context
mcp.add_middleware(OAuthTokenMiddleware())


def _get_request_context() -> Optional[Context]:
    """Return the request-scoped FastMCP context if available."""
    try:
        return request_ctx.get()
    except LookupError:
        return None


def _first_successful_result(results: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return the first non-error result from a list of entity responses."""
    for item in results:
        if not isinstance(item, dict):
            return item
        if not item.get('error'):
            return item
    return None


def _require_context_for_resource() -> Context:
    """Fetch the active request context or raise an auth error."""
    ctx = _get_request_context()
    if ctx is None:
        raise ConnectionAuthError(
            "No active request context; ensure the request is routed through an authenticated MCP connection."
        )
    return ctx

# Health endpoint for Kubernetes and monitoring systems
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
    """Standard HTTP health check endpoint for Kubernetes and monitoring systems."""
    return JSONResponse({
        "status": "healthy",
        "service": "synapse-mcp",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "0.2.0",
        "is_oauth_configured": bool(os.environ.get("SYNAPSE_OAUTH_CLIENT_ID") and
                                   os.environ.get("SYNAPSE_OAUTH_CLIENT_SECRET"))
    })

# Connection-scoped operations: no more global state!
# Each connection gets its own synapseclient and entity operations

def get_entity_operations(ctx: Context) -> Dict[str, Any]:
    """Get entity operations for this connection's synapseclient."""
    synapse_client = get_synapse_client(ctx)

    # Check if operations are already cached in context
    entity_ops = ctx.get_state("entity_ops")
    if entity_ops:
        return entity_ops

    # Create new entity operations for this connection
    entity_ops = {
        'base': BaseEntityOperations(synapse_client),
        'project': ProjectOperations(synapse_client),
        'folder': FolderOperations(synapse_client),
        'file': FileOperations(synapse_client),
        'table': TableOperations(synapse_client),
        'dataset': DatasetOperations(synapse_client),
    }

    # Cache in context for reuse
    ctx.set_state("entity_ops", entity_ops)
    return entity_ops

def get_query_builder(ctx: Context) -> QueryBuilder:
    """Get query builder for this connection's synapseclient."""
    synapse_client = get_synapse_client(ctx)

    # Check if query builder is already cached in context
    query_builder = ctx.get_state("query_builder")
    if query_builder:
        return query_builder

    # Create new query builder for this connection
    query_builder = QueryBuilder(synapse_client)

    # Cache in context for reuse
    ctx.set_state("query_builder", query_builder)
    return query_builder

# Legacy functions for backward compatibility (deprecated)
def initialize_authentication():
    """DEPRECATED: Authentication is now per-connection."""
    print("WARNING: initialize_authentication() is deprecated. Authentication is now per-connection.")
    return False, False

def authenticate_synapse_client(access_token: str):
    """DEPRECATED: Authentication is now per-connection."""
    print("WARNING: authenticate_synapse_client() is deprecated. Authentication is now per-connection.")
    return False

def is_authenticated():
    """DEPRECATED: Authentication is now per-connection."""
    print("WARNING: is_authenticated() is deprecated. Use connection_auth.is_authenticated(ctx) instead.")
    return False

def is_using_pat_auth():
    """DEPRECATED: Authentication is now per-connection."""
    print("WARNING: is_using_pat_auth() is deprecated. Check user_auth_info from connection context.")
    return False

# Entity Tools
@mcp.tool()
def get_entity(entity_id: str, ctx: Context) -> Dict[str, Any]:
    """Get a Synapse entity by ID.

    Args:
        entity_id: The Synapse ID of the entity
        ctx: FastMCP context (automatically injected)

    Returns:
        The entity as a dictionary
    """
    if not validate_synapse_id(entity_id):
        return {'error': f'Invalid Synapse ID: {entity_id}'}

    try:
        entity_ops = get_entity_operations(ctx)
        return entity_ops['base'].get_entity_by_id(entity_id)
    except ConnectionAuthError as e:
        return {'error': f'Authentication required: {e}', 'entity_id': entity_id}
    except Exception as e:
        return {'error': str(e), 'entity_id': entity_id}

@mcp.tool()
def get_entity_annotations(entity_id: str, ctx: Context) -> Dict[str, Any]:
    """Get annotations for an entity.

    Args:
        entity_id: The Synapse ID of the entity
        ctx: FastMCP context (automatically injected)

    Returns:
        The entity annotations as a dictionary
    """
    if not validate_synapse_id(entity_id):
        return {'error': f'Invalid Synapse ID: {entity_id}'}

    try:
        entity_ops = get_entity_operations(ctx)
        annotations = entity_ops['base'].get_entity_annotations(entity_id)
        return format_annotations(annotations)
    except ConnectionAuthError as e:
        return {'error': f'Authentication required: {e}', 'entity_id': entity_id}
    except Exception as e:
        return {'error': str(e), 'entity_id': entity_id}

@mcp.tool()
def get_entity_children(entity_id: str, ctx: Context) -> List[Dict[str, Any]]:
    """Get child entities of a container entity.

    Args:
        entity_id: The Synapse ID of the container entity
        ctx: FastMCP context (automatically injected)

    Returns:
        List of child entities
    """
    if not validate_synapse_id(entity_id):
        return [{'error': f'Invalid Synapse ID: {entity_id}'}]

    try:
        entity_ops = get_entity_operations(ctx)
        # Determine the entity type
        entity = entity_ops['base'].get_entity_by_id(entity_id)
        entity_type = entity.get('type', '').lower()

        if entity_type == 'project':
            return entity_ops['project'].get_project_children(entity_id)
        elif entity_type == 'folder':
            return entity_ops['folder'].get_folder_children(entity_id)
        else:
            return [{'error': f'Entity {entity_id} is not a container entity'}]
    except ConnectionAuthError as e:
        return [{'error': f'Authentication required: {e}', 'entity_id': entity_id}]
    except Exception as e:
        return [{'error': str(e), 'entity_id': entity_id}]

# Query Tools
@mcp.tool()
def search_entities(search_term: str, ctx: Context, entity_type: Optional[str] = None, parent_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Search for Synapse entities.

    Args:
        search_term: Term to search for
        ctx: FastMCP context (automatically injected)
        entity_type: Type of entity to search for (optional)
        parent_id: Parent entity ID to filter by (optional)

    Returns:
        List of entities matching the search
    """
    # Build search parameters
    params = {"name": search_term}
    if entity_type:
        params["entity_type"] = entity_type
    if parent_id:
        params["parent_id"] = parent_id
    return query_entities(ctx, **params)

@mcp.tool()
def query_entities(ctx: Context, entity_type: Optional[str] = None, parent_id: Optional[str] = None,
                  name: Optional[str] = None, annotations: Optional[str] = None) -> List[Dict[str, Any]]:
    """Query entities based on various criteria.

    Args:
        ctx: FastMCP context (automatically injected)
        entity_type: Type of entity to query (project, folder, file, table, dataset)
        parent_id: Parent entity ID to filter by
        name: Entity name to filter by
        annotations: Annotations to filter by (as a JSON string)

    Returns:
        List of entities matching the query
    """
    try:
        query_builder = get_query_builder(ctx)
        import json
        # Build query parameters
        params: Dict[str, Any] = {}
        if entity_type:
            params['entity_type'] = entity_type
        if parent_id:
            params['parent_id'] = parent_id
        if name:
            params['name'] = name
        if annotations:
            params['annotations'] = json.loads(annotations)

        # Build and execute query
        query = query_builder.build_combined_query(params)
        return query_builder.execute_query(query)
    except ConnectionAuthError as e:
        return [{'error': f'Authentication required: {e}'}]
    except Exception as e:
        error_params = {
            'entity_type': entity_type,
            'parent_id': parent_id,
            'name': name,
            'annotations': annotations,
        }
        sanitized_params = {k: v for k, v in error_params.items() if v is not None}
        return [{'error': str(e), 'params': sanitized_params}]

@mcp.tool()
def query_table(table_id: str, query: str, ctx: Context) -> Dict[str, Any]:
    """Query a Synapse table.

    Args:
        table_id: The Synapse ID of the table
        query: SQL-like query string
        ctx: FastMCP context (automatically injected)

    Returns:
        Query results
    """
    if not validate_synapse_id(table_id):
        return {'error': f'Invalid Synapse ID: {table_id}'}

    try:
        entity_ops = get_entity_operations(ctx)
        return entity_ops['table'].query_table(table_id, query)
    except ConnectionAuthError as e:
        return {'error': f'Authentication required: {e}', 'table_id': table_id}
    except Exception as e:
        return {'error': str(e), 'table_id': table_id, 'query': query}

@mcp.tool()
def get_datasets_as_croissant(ctx: Context) -> Dict[str, Any]:
    """Get public datasets in Croissant metadata format.

    Args:
        ctx: FastMCP context (automatically injected)

    Returns:
        Datasets in Croissant metadata format
    """
    table_id = "syn61609402"
    query_result = query_table.fn(table_id, f"SELECT * FROM {table_id}", ctx)
    if 'error' in query_result:
        return query_result
    return convert_to_croissant(query_result)


# Entity Resources
@mcp.resource("entities/{id_or_name}")
def get_entity_by_id_or_name(id_or_name: str) -> Dict[str, Any]:
    """Get entity by ID or name."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}

    if validate_synapse_id(id_or_name):
        return get_entity.fn(id_or_name, ctx)

    results = query_entities.fn(ctx, name=id_or_name)
    entity = _first_successful_result(results) if results else None
    if entity:
        return entity
    return {'error': f'Entity not found: {id_or_name}'}


@mcp.resource("entities/{id}/annotations")
def get_entity_annotations_resource(id: str) -> Dict[str, Any]:
    """Get entity annotations."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}
    return get_entity_annotations.fn(id, ctx)


@mcp.resource("entities/{id}/children")
def get_entity_children_resource(id: str) -> List[Dict[str, Any]]:
    """Get entity children."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return [{'error': str(exc)}]
    return get_entity_children.fn(id, ctx)


@mcp.resource("entities/{entity_type}")
def query_entities_by_type(entity_type: str) -> List[Dict[str, Any]]:
    """Query entities by type."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return [{'error': str(exc)}]
    return query_entities.fn(ctx, entity_type=entity_type)


@mcp.resource("entities/parent/{parent_id}")
def query_entities_by_parent(parent_id: str) -> List[Dict[str, Any]]:
    """Query entities by parent ID."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return [{'error': str(exc)}]
    return query_entities.fn(ctx, parent_id=parent_id)


# Project Resources
@mcp.resource("projects/{id_or_name}")
def get_project_by_id_or_name(id_or_name: str) -> Dict[str, Any]:
    """Get project by ID or name."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}

    if validate_synapse_id(id_or_name):
        entity = get_entity.fn(id_or_name, ctx)
    else:
        results = query_entities.fn(ctx, name=id_or_name, entity_type='project')
        entity = _first_successful_result(results) if results else None

    if entity and entity.get('type', '').lower() == 'project':
        return entity
    if entity and entity.get('error'):
        return entity
    return {'error': f'Project not found: {id_or_name}'}


@mcp.resource("projects/{id}/annotations")
def get_project_annotations(id: str) -> Dict[str, Any]:
    """Get project annotations."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}
    return get_entity_annotations.fn(id, ctx)


@mcp.resource("projects/{id}/children")
def get_project_children(id: str) -> List[Dict[str, Any]]:
    """Get project children."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return [{'error': str(exc)}]
    return get_entity_children.fn(id, ctx)


@mcp.resource("projects/{id}/parent")
def get_project_parent(id: str) -> Dict[str, Any]:
    """Get project parent."""
    return {'error': 'Projects do not have parents in Synapse'}


# Dataset Resources
@mcp.resource("datasets/{id_or_name}")
def get_dataset_by_id_or_name(id_or_name: str) -> Dict[str, Any]:
    """Get dataset by ID or name."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}

    if validate_synapse_id(id_or_name):
        entity = get_entity.fn(id_or_name, ctx)
    else:
        results = query_entities.fn(ctx, name=id_or_name, entity_type='dataset')
        entity = _first_successful_result(results) if results else None

    if entity and entity.get('type', '').lower() == 'dataset':
        return entity
    if entity and entity.get('error'):
        return entity
    return {'error': f'Dataset not found: {id_or_name}'}


@mcp.resource("datasets/{id}/annotations")
def get_dataset_annotations(id: str) -> Dict[str, Any]:
    """Get dataset annotations."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}
    return get_entity_annotations.fn(id, ctx)


@mcp.resource("datasets/{id}/children")
def get_dataset_children(id: str) -> List[Dict[str, Any]]:
    """Get dataset children."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return [{'error': str(exc)}]
    return get_entity_children.fn(id, ctx)


@mcp.resource("datasets/{id}/parent")
def get_dataset_parent(id: str) -> Dict[str, Any]:
    """Get dataset parent."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}
    entity = get_entity.fn(id, ctx)
    parent_id = entity.get('parentId') if isinstance(entity, dict) else None
    if not parent_id:
        return {'error': 'Dataset has no parent'}
    return get_entity.fn(parent_id, ctx)


# Folder Resources
@mcp.resource("folders/{id_or_name}")
def get_folder_by_id_or_name(id_or_name: str) -> Dict[str, Any]:
    """Get folder by ID or name."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}

    if validate_synapse_id(id_or_name):
        entity = get_entity.fn(id_or_name, ctx)
    else:
        results = query_entities.fn(ctx, name=id_or_name, entity_type='folder')
        entity = _first_successful_result(results) if results else None

    if entity and entity.get('type', '').lower() == 'folder':
        return entity
    if entity and entity.get('error'):
        return entity
    return {'error': f'Folder not found: {id_or_name}'}


@mcp.resource("folders/{id}/annotations")
def get_folder_annotations(id: str) -> Dict[str, Any]:
    """Get folder annotations."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}
    return get_entity_annotations.fn(id, ctx)


@mcp.resource("folders/{id}/children")
def get_folder_children(id: str) -> List[Dict[str, Any]]:
    """Get folder children."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return [{'error': str(exc)}]
    return get_entity_children.fn(id, ctx)


@mcp.resource("folders/{id}/parent")
def get_folder_parent(id: str) -> Dict[str, Any]:
    """Get folder parent."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}
    entity = get_entity.fn(id, ctx)
    parent_id = entity.get('parentId') if isinstance(entity, dict) else None
    if not parent_id:
        return {'error': 'Folder has no parent'}
    return get_entity.fn(parent_id, ctx)


# File Resources
@mcp.resource("files/{id_or_name}")
def get_file_by_id_or_name(id_or_name: str) -> Dict[str, Any]:
    """Get file by ID or name."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}

    if validate_synapse_id(id_or_name):
        entity = get_entity.fn(id_or_name, ctx)
    else:
        results = query_entities.fn(ctx, name=id_or_name, entity_type='file')
        entity = _first_successful_result(results) if results else None

    if entity and entity.get('type', '').lower() == 'file':
        return entity
    if entity and entity.get('error'):
        return entity
    return {'error': f'File not found: {id_or_name}'}


@mcp.resource("files/{id}/annotations")
def get_file_annotations(id: str) -> Dict[str, Any]:
    """Get file annotations."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}
    return get_entity_annotations.fn(id, ctx)


@mcp.resource("files/{id}/children")
def get_file_children(id: str) -> List[Dict[str, Any]]:
    """Get file children."""
    return [{'error': 'Files do not have children in Synapse'}]


@mcp.resource("files/{id}/parent")
def get_file_parent(id: str) -> Dict[str, Any]:
    """Get file parent."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}
    entity = get_entity.fn(id, ctx)
    parent_id = entity.get('parentId') if isinstance(entity, dict) else None
    if not parent_id:
        return {'error': 'File has no parent'}
    return get_entity.fn(parent_id, ctx)


# Table Resources
@mcp.resource("tables/{id_or_name}")
def get_table_by_id_or_name(id_or_name: str) -> Dict[str, Any]:
    """Get table by ID or name."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}

    if validate_synapse_id(id_or_name):
        entity = get_entity.fn(id_or_name, ctx)
    else:
        results = query_entities.fn(ctx, name=id_or_name, entity_type='table')
        entity = _first_successful_result(results) if results else None

    if entity and entity.get('type', '').lower() == 'table':
        return entity
    if entity and entity.get('error'):
        return entity
    return {'error': f'Table not found: {id_or_name}'}


@mcp.resource("tables/{id}/annotations")
def get_table_annotations(id: str) -> Dict[str, Any]:
    """Get table annotations."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}
    return get_entity_annotations.fn(id, ctx)


@mcp.resource("tables/{id}/children")
def get_table_children(id: str) -> List[Dict[str, Any]]:
    """Get table children."""
    return [{'error': 'Tables do not have children in Synapse'}]


@mcp.resource("tables/{id}/parent")
def get_table_parent(id: str) -> Dict[str, Any]:
    """Get table parent."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}
    entity = get_entity.fn(id, ctx)
    parent_id = entity.get('parentId') if isinstance(entity, dict) else None
    if not parent_id:
        return {'error': 'Table has no parent'}
    return get_entity.fn(parent_id, ctx)


@mcp.resource("table/{id}/{query}")
def query_table_resource(id: str, query: str) -> Dict[str, Any]:
    """Query a table with SQL-like syntax."""
    try:
        ctx = _require_context_for_resource()
    except ConnectionAuthError as exc:
        return {'error': str(exc)}

    import urllib.parse

    decoded_query = urllib.parse.unquote(query)
    return query_table.fn(id, decoded_query, ctx)

from typing import Any, Dict


def format_annotations(annotations: Any) -> Dict[str, Any]:
    """Format Synapse annotations as a dictionary.
    
    Args:
        annotations: The Synapse annotations
        
    Returns:
        The annotations as a dictionary
    """
    if hasattr(annotations, 'to_dict'):
        return annotations.to_dict()
    elif isinstance(annotations, dict):
        return annotations
    else:
        # Try to extract annotations from the object
        result = {}
        if hasattr(annotations, 'id'):
            result['id'] = annotations.id
        if hasattr(annotations, 'etag'):
            result['etag'] = annotations.etag
        
        # Extract annotation values
        for key in dir(annotations):
            if not key.startswith('_') and key not in ['id', 'etag']:
                value = getattr(annotations, key)
                if not callable(value):
                    result[key] = value
        
        return result

def validate_synapse_id(entity_id: str) -> bool:
    """Validate a Synapse ID format.
    
    Args:
        entity_id: The Synapse ID to validate
        
    Returns:
        True if the ID is valid, False otherwise
    """
    # Synapse IDs typically start with 'syn' followed by numbers
    if not entity_id.startswith('syn'):
        return False
    
    # Check if the rest of the ID is numeric
    id_part = entity_id[3:]
    return id_part.isdigit()

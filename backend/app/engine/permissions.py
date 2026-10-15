from typing import Tuple, Optional
from app.models.schemas import UserContext, DocumentContext

ROLE_CLEARANCE = {
    "intern": 0,       # Can only access public documents
    "general": 1,      # Public + Internal
    "engineer": 2,     # Public + Internal + Confidential
    "admin": 3,        # Full access including Restricted
}

CLEARANCE_LEVELS = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
}


def check_document_permission(
    user_context: Optional[UserContext],
    document_context: Optional[DocumentContext]
) -> Tuple[bool, str]:
    """
    Validates whether the user's role has sufficient clearance to access
    or query the specified document context.
    Returns (granted, reason).
    """
    if not document_context:
        return True, "No document restrictions applied."

    required_clearance = (document_context.required_clearance or "public").lower()
    required_clearance_score = CLEARANCE_LEVELS.get(required_clearance, 0)

    # If clearance is protected (internal, confidential, restricted), require a valid doc_id
    doc_id = (document_context.doc_id or "").strip()
    if required_clearance_score > 0 and not doc_id:
        return False, "Access Denied: Missing valid document identifier for protected resource."

    # If no doc_id and public clearance, allow
    if not doc_id and required_clearance_score == 0:
        return True, "No document restrictions applied."

    user_role = (user_context.role if user_context else "general").lower()
    user_clearance_score = ROLE_CLEARANCE.get(user_role, 0)

    if user_clearance_score < required_clearance_score:
        return False, "Access Denied: Insufficient permissions for requested document."

    return True, "Document access authorized."

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
    if not document_context or not document_context.doc_id:
        # No specific document requested; general prompt
        return True, "No document restrictions applied."

    user_role = (user_context.role if user_context else "general").lower()
    required_clearance = (document_context.required_clearance or "public").lower()

    user_clearance_score = ROLE_CLEARANCE.get(user_role, 0)
    required_clearance_score = CLEARANCE_LEVELS.get(required_clearance, 0)

    if user_clearance_score < required_clearance_score:
        return False, (
            f"Access Denied: Role '{user_role}' lacks required clearance "
            f"'{required_clearance}' for document '{document_context.title or document_context.doc_id}'."
        )

    return True, "Document access authorized."

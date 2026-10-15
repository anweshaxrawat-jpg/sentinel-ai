from typing import List
from app.models.schemas import DetectedEntity


def mask_text(text: str, entities: List[DetectedEntity]) -> str:
    """
    Replaces detected sensitive spans with redaction tokens like [REDACTED_EMAIL].
    Processes replacements from right to left to maintain valid slice offsets.
    """
    if not entities:
        return text

    # Remove overlapping entities, prioritizing earlier/longer matches
    sorted_entities = sorted(entities, key=lambda e: (e.start, -e.end))
    filtered_entities: List[DetectedEntity] = []

    last_end = -1
    for ent in sorted_entities:
        if ent.start >= last_end:
            filtered_entities.append(ent)
            last_end = ent.end

    # Replace from back to front
    result = text
    for ent in reversed(filtered_entities):
        token = f"[REDACTED_{ent.entity_type}]"
        result = result[: ent.start] + token + result[ent.end :]

    return result


def generate_sanitized_preview(
    text: str,
    max_length: int = 60,
    is_blocked: bool = False,
    blocked_category: str = None,
) -> str:
    """
    Generates a safe preview string for audit logging.
    - If the request was BLOCKED (e.g. injection, permissions, credentials),
      strictly returns a generic non-sensitive preview tag, NEVER raw text.
    - For allowed or masked requests, safely truncates the already masked text.
    """
    if is_blocked:
        category = (blocked_category or "SECURITY_VIOLATION").strip().upper()
        return f"[BLOCKED: {category}]"

    preview = text.strip().replace("\n", " ")
    if len(preview) > max_length:
        return preview[:max_length] + "..."
    return preview

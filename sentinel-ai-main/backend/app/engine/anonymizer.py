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


def generate_sanitized_preview(text: str, max_length: int = 60) -> str:
    """
    Generates a safe preview string from an already masked prompt.
    Truncates to max_length and adds an ellipsis if needed.
    NEVER call this on unmasked/raw prompts.
    """
    preview = text.strip().replace("\n", " ")
    if len(preview) > max_length:
        return preview[:max_length] + "..."
    return preview

import re
from typing import Tuple

# Common prompt injection, jailbreak, and system override patterns
# Deterministic heuristic patterns for prompt injection, jailbreaks, and system overrides
INJECTION_PATTERNS = [
    # Instruction & rule override variations (ignore the previous, forget all prior, disregard guidance)
    re.compile(
        r"(?i)\b(?:ignore|disregard|forget|override|drop|cancel|reset)\s+"
        r"(?:all\s+|the\s+|any\s+|every\s+|your\s+|system\s+)*"
        r"(?:previous|prior|above|earlier|system|existing|initial)?\s*"
        r"(?:instructions|rules|guidelines|guidance|directions|prompts|commands|constraints)\b"
    ),
    # Persona & jailbreak variations (DAN, unfiltered, no rules)
    re.compile(
        r"(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+"
        r"(?:an?\s+)?(?:DAN|unfiltered|jailbroken|unrestricted|evil\s+ai)\b"
    ),
    re.compile(
        r"(?i)\bpretend\s+(?:you\s+have|there\s+are)\s+no\s+"
        r"(?:safety|ethics|rules|restrictions|limits|guidelines)\b"
    ),
    re.compile(r"(?i)\benter\s+(?:DAN(?:\s+mode)?|developer\s+mode|jailbreak\s+mode)\b"),
    # Filter bypass variations (bypass the security rules, disable filters)
    re.compile(
        r"(?i)\b(?:bypass|disable|circumvent|ignore)\s+"
        r"(?:all\s+|the\s+|any\s+)*"
        r"(?:content\s+|safety\s+|security\s+)*"
        r"(?:filters|checks|rules|safeguards|restrictions|guidelines)\b"
    ),
    # System prompt exfiltration
    re.compile(
        r"(?i)\b(?:repeat|reveal|print|show|output|leak)\s+"
        r"(?:the\s+|your\s+)?(?:system\s+prompt|initial\s+prompt|hidden\s+prompt|instructions\s+above|developer\s+instructions)\b"
    ),
]


def detect_prompt_injection(prompt: str) -> Tuple[bool, str]:
    """
    Checks if the prompt contains known prompt injection or jailbreak patterns.
    Returns a tuple of (is_injection, reason).
    Note: Deterministic heuristics provide defense-in-depth but do not guarantee catching every attack.
    """
    for pattern in INJECTION_PATTERNS:
        match = pattern.search(prompt)
        if match:
            # Generic message without reflecting matched attacker input
            return True, "Detected potential prompt injection or policy override."

    return False, ""

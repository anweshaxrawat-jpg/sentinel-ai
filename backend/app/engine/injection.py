import re
from typing import Tuple

# Common prompt injection, jailbreak, and system override patterns
INJECTION_PATTERNS = [
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b"),
    re.compile(r"(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior|system)\s+rules\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(?:DAN|unfiltered|jailbroken|unrestricted)\b"),
    re.compile(r"(?i)\bpretend\s+you\s+have\s+no\s+(?:safety|ethics|rules|restrictions)\b"),
    re.compile(r"(?i)\brepeat\s+(?:the\s+)?(?:system\s+prompt|initial\s+prompt|instructions\s+above)\b"),
    re.compile(r"(?i)\breveal\s+(?:your\s+)?(?:system\s+prompt|developer\s+mode|internal\s+instructions)\b"),
    re.compile(r"(?i)\benter\s+(?:DAN\s+mode|developer\s+mode)\b"),
    re.compile(r"(?i)\bbypass\s+(?:all\s+)?(?:content\s+filters|security\s+checks)\b"),
]


def detect_prompt_injection(prompt: str) -> Tuple[bool, str]:
    """
    Checks if the prompt contains known prompt injection or jailbreak patterns.
    Returns a tuple of (is_injection, reason).
    """
    for pattern in INJECTION_PATTERNS:
        match = pattern.search(prompt)
        if match:
            return True, f"Detected potential prompt injection attempt: '{match.group(0)}'"

    return False, ""

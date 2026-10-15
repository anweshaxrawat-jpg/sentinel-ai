import re
from typing import List
from app.models.schemas import DetectedEntity, EntitySeverity

# Pre-compiled regular expressions for real PII and Secret detection
PII_PATTERNS = [
    {
        "type": "EMAIL",
        "label": "Email Address",
        "severity": EntitySeverity.LOW,
        "regex": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    },
    {
        "type": "PHONE_NUMBER",
        "label": "Phone Number",
        "severity": EntitySeverity.LOW,
        "regex": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b"),
    },
    {
        "type": "SSN",
        "label": "US Social Security Number",
        "severity": EntitySeverity.CRITICAL,
        "regex": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    },
    {
        "type": "CREDIT_CARD",
        "label": "Credit Card Number",
        "severity": EntitySeverity.CRITICAL,
        "regex": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
    },
]

SECRET_PATTERNS = [
    {
        "type": "OPENAI_API_KEY",
        "label": "OpenAI API Key",
        "severity": EntitySeverity.CRITICAL,
        "regex": re.compile(r"\bsk-(?:proj-)?[a-zA-Z0-9_-]{20,}\b"),
    },
    {
        "type": "AWS_ACCESS_KEY",
        "label": "AWS Access Key ID",
        "severity": EntitySeverity.CRITICAL,
        "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    },
    {
        "type": "GITHUB_TOKEN",
        "label": "GitHub Personal Access Token",
        "severity": EntitySeverity.CRITICAL,
        "regex": re.compile(r"\b(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})\b"),
    },
    {
        "type": "PRIVATE_KEY",
        "label": "Private Key Header",
        "severity": EntitySeverity.CRITICAL,
        "regex": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    },
    {
        "type": "GENERIC_SECRET",
        "label": "Generic API Secret / Password",
        "severity": EntitySeverity.HIGH,
        "regex": re.compile(r"(?i)\b(?:api_key|apikey|secret|password|passwd|auth_token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{8,})['\"]?"),
    },
]


def detect_entities(text: str) -> List[DetectedEntity]:
    """
    Scans the given input text for PII and sensitive secrets.
    Returns a list of DetectedEntity objects with positions and severity levels.
    """
    detected: List[DetectedEntity] = []

    # Check PII
    for item in PII_PATTERNS:
        for match in item["regex"].finditer(text):
            detected.append(
                DetectedEntity(
                    entity_type=item["type"],
                    label=item["label"],
                    severity=item["severity"],
                    start=match.start(),
                    end=match.end(),
                )
            )

    # Check Secrets
    for item in SECRET_PATTERNS:
        for match in item["regex"].finditer(text):
            detected.append(
                DetectedEntity(
                    entity_type=item["type"],
                    label=item["label"],
                    severity=item["severity"],
                    start=match.start(),
                    end=match.end(),
                )
            )

    # Sort matches by start position in ascending order
    detected.sort(key=lambda x: x.start)
    return detected

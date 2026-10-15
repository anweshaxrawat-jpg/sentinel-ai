from typing import List, Tuple, Optional
from app.models.schemas import (
    GatewayAction,
    DetectedEntity,
    EntitySeverity,
    PolicyConfig,
)


def evaluate_policy(
    entities: List[DetectedEntity],
    is_injection: bool,
    injection_reason: str,
    permission_granted: bool,
    permission_reason: str,
    config: PolicyConfig,
) -> Tuple[GatewayAction, float, Optional[str]]:
    """
    Evaluates scan results against active security policies.
    Returns (action, risk_score, blocked_reason).
    """
    # 1. Document Permissions check
    if config.enforce_document_permissions and not permission_granted:
        return GatewayAction.BLOCK, 1.0, permission_reason

    # 2. Prompt Injection check
    if config.block_on_injection and is_injection:
        return GatewayAction.BLOCK, 1.0, injection_reason

    # 3. Check for high/critical secrets (API keys, private keys, passwords)
    has_critical_secrets = any(
        e.severity in [EntitySeverity.HIGH, EntitySeverity.CRITICAL]
        for e in entities
    )

    if config.block_on_secrets and has_critical_secrets:
        return (
            GatewayAction.BLOCK,
            0.9,
            "Blocked due to exposure of sensitive secrets or credentials.",
        )

    # 4. Check for PII (Email, Phone, etc.)
    has_pii = len(entities) > 0

    if has_pii:
        if config.mask_pii:
            # Masking allowed
            return GatewayAction.MASK, 0.4, None
        else:
            return GatewayAction.BLOCK, 0.7, "Blocked due to PII detection policy."

    # 5. Clean request
    return GatewayAction.ALLOW, 0.0, None

from fastapi import APIRouter, HTTPException
from app.models.schemas import ScanRequest, ScanResponse, GatewayAction
from app.engine.detector import detect_entities
from app.engine.anonymizer import mask_text, generate_sanitized_preview
from app.engine.injection import detect_prompt_injection
from app.engine.permissions import check_document_permission
from app.engine.policy import evaluate_policy
from app.services.mock_llm import mock_llm_service
from app.services.storage import storage

router = APIRouter(prefix="/gateway", tags=["Gateway"])


@router.post("/scan", response_model=ScanResponse)
def scan_and_process_prompt(request: ScanRequest):
    """
    Main gateway entrypoint:
    1. Validates document permissions (user role vs document clearance).
    2. Inspects for prompt injection attempts.
    3. Detects PII and sensitive secrets.
    4. Evaluates active policies (ALLOW, MASK, or BLOCK).
    5. Mask prompt if needed; NEVER forward raw secrets.
    6. Proxies sanitized prompt to the Mock LLM (if permitted).
    7. Saves privacy-first audit log (sanitized preview ONLY, never raw prompt).
    """
    prompt = request.prompt
    user = request.user_context
    doc = request.document_context

    # 1. Document permission check
    perm_granted, perm_reason = check_document_permission(user, doc)

    # 2. Prompt injection check
    is_injection, injection_reason = detect_prompt_injection(prompt)

    # 3. Detect PII and secrets
    detected_entities = detect_entities(prompt)

    # 4. Anonymize/mask text
    sanitized_prompt = mask_text(prompt, detected_entities)

    # 5. Evaluate policy
    current_config = storage.get_policy_config()
    action, risk_score, blocked_reason = evaluate_policy(
        entities=detected_entities,
        is_injection=is_injection,
        injection_reason=injection_reason,
        permission_granted=perm_granted,
        permission_reason=perm_reason,
        config=current_config,
    )

    # 6. Call Mock LLM only if allowed or masked
    llm_output = None
    if action in [GatewayAction.ALLOW, GatewayAction.MASK]:
        llm_output = mock_llm_service.generate_response(sanitized_prompt)

    # 7. Safe audit log (Zero raw sensitive data stored!)
    safe_preview = generate_sanitized_preview(sanitized_prompt)
    detected_types = [e.entity_type for e in detected_entities]
    if is_injection:
        detected_types.append("PROMPT_INJECTION")
    if not perm_granted:
        detected_types.append("UNAUTHORIZED_ACCESS")

    storage.add_audit_log(
        action=action,
        risk_score=risk_score,
        detected_types=detected_types,
        sanitized_preview=safe_preview,
        user_role=user.role if user else "general",
        blocked_reason=blocked_reason,
    )

    return ScanResponse(
        status="blocked" if action == GatewayAction.BLOCK else "allowed",
        action=action,
        sanitized_prompt=sanitized_prompt,
        risk_score=risk_score,
        entities_detected=detected_entities,
        injection_detected=is_injection,
        permission_granted=perm_granted,
        blocked_reason=blocked_reason,
        llm_response=llm_output,
    )

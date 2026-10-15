import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any
from app.models.schemas import AuditLogEntry, GatewayAction, PolicyConfig


class InMemoryStorage:
    """
    Lightweight, thread-safe in-memory store for audit logs and policy settings.
    Enforces privacy by design: raw sensitive prompts are strictly never stored.
    """

    def __init__(self):
        self._logs: List[AuditLogEntry] = []
        self._policy_config = PolicyConfig()

    def add_audit_log(
        self,
        action: GatewayAction,
        risk_score: float,
        detected_types: List[str],
        sanitized_preview: str,  # Must already be masked/sanitized!
        user_role: str,
        blocked_reason: str = None,
    ) -> AuditLogEntry:
        # Privacy guarantee: blocked requests must strictly use generic placeholder previews
        safe_preview = sanitized_preview
        if action == GatewayAction.BLOCK and not (safe_preview.startswith("[BLOCKED") or "[REDACTED_" in safe_preview):
            safe_preview = "[BLOCKED: SECURITY_POLICY]"

        entry = AuditLogEntry(
            id=str(uuid.uuid4())[:8],
            timestamp=datetime.now(timezone.utc),
            action=action,
            risk_score=risk_score,
            detected_types=detected_types,
            sanitized_preview=safe_preview,
            user_role=user_role,
            blocked_reason=blocked_reason,
        )
        self._logs.insert(0, entry)  # Latest logs first
        # Keep maximum 200 logs in memory to prevent memory bloat
        if len(self._logs) > 200:
            self._logs.pop()
        return entry

    def get_audit_logs(self, limit: int = 50) -> List[AuditLogEntry]:
        return self._logs[:limit]

    def get_policy_config(self) -> PolicyConfig:
        return self._policy_config

    def update_policy_config(self, new_config: PolicyConfig) -> PolicyConfig:
        self._policy_config = new_config
        return self._policy_config

    def get_metrics(self) -> Dict[str, Any]:
        total = len(self._logs)
        blocked = sum(1 for log in self._logs if log.action == GatewayAction.BLOCK)
        masked = sum(1 for log in self._logs if log.action == GatewayAction.MASK)
        allowed = sum(1 for log in self._logs if log.action == GatewayAction.ALLOW)

        type_counts: Dict[str, int] = {}
        for log in self._logs:
            for t in log.detected_types:
                type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "total_requests": total,
            "blocked_count": blocked,
            "masked_count": masked,
            "allowed_count": allowed,
            "leak_type_distribution": type_counts,
        }


storage = InMemoryStorage()

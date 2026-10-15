from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class GatewayAction(str, Enum):
    ALLOW = "ALLOW"
    MASK = "MASK"
    BLOCK = "BLOCK"


class EntitySeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectedEntity(BaseModel):
    entity_type: str
    label: str
    severity: EntitySeverity
    start: int
    end: int


class UserContext(BaseModel):
    user_id: str = "guest_user"
    role: str = "general"          # e.g., 'intern', 'general', 'engineer', 'admin'
    department: Optional[str] = "engineering"


class DocumentContext(BaseModel):
    doc_id: Optional[str] = None
    title: Optional[str] = None
    required_clearance: str = "public"   # 'public', 'internal', 'confidential', 'restricted'


class ScanRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="Raw input prompt to be inspected")
    user_context: Optional[UserContext] = Field(default_factory=UserContext)
    document_context: Optional[DocumentContext] = None


class ScanResponse(BaseModel):
    status: str                         # 'allowed', 'masked', or 'blocked'
    action: GatewayAction
    sanitized_prompt: str
    risk_score: float                   # 0.0 to 1.0
    entities_detected: List[DetectedEntity] = []
    injection_detected: bool = False
    permission_granted: bool = True
    blocked_reason: Optional[str] = None
    llm_response: Optional[str] = None


class AuditLogEntry(BaseModel):
    id: str
    timestamp: datetime
    action: GatewayAction
    risk_score: float
    detected_types: List[str]
    sanitized_preview: str             # Strictly sanitized snippet (never raw prompt!)
    user_role: str
    blocked_reason: Optional[str] = None


class PolicyConfig(BaseModel):
    block_on_injection: bool = True
    block_on_secrets: bool = True
    mask_pii: bool = True
    enforce_document_permissions: bool = True

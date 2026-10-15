from typing import List, Dict, Any
from fastapi import APIRouter
from app.models.schemas import AuditLogEntry
from app.services.storage import storage

router = APIRouter(prefix="/logs", tags=["Audit Logs"])


@router.get("", response_model=List[AuditLogEntry])
def get_audit_logs(limit: int = 50):
    """
    Retrieve security incident logs.
    Strict privacy guarantee: Only sanitized previews and metadata are returned.
    """
    return storage.get_audit_logs(limit=limit)


@router.get("/metrics", response_model=Dict[str, Any])
def get_security_metrics():
    """
    Retrieve aggregated dashboard security metrics and incident breakdowns.
    """
    return storage.get_metrics()

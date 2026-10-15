from fastapi import APIRouter
from app.models.schemas import PolicyConfig
from app.services.storage import storage

router = APIRouter(prefix="/rules", tags=["Policy Rules"])


@router.get("", response_model=PolicyConfig)
def get_policy_rules():
    """
    Get the currently active security policies.
    """
    return storage.get_policy_config()


@router.post("", response_model=PolicyConfig)
def update_policy_rules(new_config: PolicyConfig):
    """
    Update active security policies (e.g., toggle blocking/masking).
    """
    return storage.update_policy_config(new_config)

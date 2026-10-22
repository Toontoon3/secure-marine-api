import logging
from typing import Optional

from fastapi import Request
from sqlalchemy.orm import Session

from app.models.audit import AuditAction, AuditLog, ResourceType

logger = logging.getLogger(__name__)


def get_client_ip(request: Request) -> str:
    """Extract real client IP, respecting X-Forwarded-For from Nginx."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def write_audit_log(
    db: Session,
    action: AuditAction,
    resource_type: ResourceType,
    request: Request,
    user_id=None,
    resource_id: Optional[str] = None,
    success: bool = True,
    error_detail: Optional[str] = None,
) -> None:
    """
    Write a single audit log entry and commit it.

    Never raises — audit log failures must not break the main request.
    This is a shared helper used across all routers so audit log
    writing is consistent everywhere.

    Usage:
        from app.core.audit import write_audit_log
        from app.models.audit import AuditAction, ResourceType

        write_audit_log(
            db=db,
            action=AuditAction.DOWNLOAD,
            resource_type=ResourceType.DATASET,
            request=request,
            user_id=current_user.id,
            resource_id=str(dataset.id),
        )
    """
    try:
        log = AuditLog.create(
            action=action,
            resource_type=resource_type,
            user_id=user_id,
            resource_id=resource_id,
            success=success,
            error_detail=error_detail,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", "")[:500],
            endpoint=str(request.url.path),
            http_method=request.method,
        )
        db.add(log)
        db.commit()
    except Exception as e:
        logger.error(f"Audit log write failed: {e}")
        db.rollback()

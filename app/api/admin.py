import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from app.core.rbac import require_sys_admin
from app.database import get_db
from app.models.audit import AuditAction, AuditLog, ResourceType
from app.models.user import User
from app.schemas.user import UserListResponse, UserResponse

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin",
    tags=["Admin"],
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "System administrator access required"},
    },
)


# ------------------------------------------------------------------ #
#  GET /admin/audit-logs                                              #
# ------------------------------------------------------------------ #

@router.get(
    "/audit-logs",
    status_code=status.HTTP_200_OK,
    summary="View audit logs (sys_admin only)",
    description=(
        "Return a paginated, filterable list of all audit log entries. "
        "Restricted to **sys_admin** role. "
        "This endpoint itself is logged."
    ),
)
def get_audit_logs(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    user_id: Optional[uuid.UUID] = Query(None, description="Filter by user"),
    action: Optional[str] = Query(None, description="Filter by action e.g. LOGIN"),
    success: Optional[bool] = Query(None, description="Filter by success/failure"),
    ip_address: Optional[str] = Query(None, description="Filter by IP address"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_sys_admin),
):
    """
    Return audit logs with optional filters.
    Every call to this endpoint is itself logged.
    """
    query = db.query(AuditLog)

    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if action:
        query = query.filter(AuditLog.action == action.upper())
    if success is not None:
        query = query.filter(AuditLog.success == success)
    if ip_address:
        query = query.filter(AuditLog.ip_address == ip_address)

    total = query.count()
    logs = (
        query
        .order_by(AuditLog.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    # Log this access — viewing audit logs is itself an auditable event
    try:
        log = AuditLog.create(
            action=AuditAction.VIEW_AUDIT_LOGS,
            resource_type=ResourceType.SYSTEM,
            user_id=current_user.id,
            success=True,
            ip_address=request.client.host if request.client else "unknown",
            endpoint=str(request.url.path),
            http_method=request.method,
        )
        db.add(log)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to log audit log access: {e}")

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "logs": [
            {
                "id": str(log.id),
                "user_id": str(log.user_id) if log.user_id else None,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "success": log.success,
                "error_detail": log.error_detail,
                "ip_address": log.ip_address,
                "endpoint": log.endpoint,
                "http_method": log.http_method,
                "created_at": log.created_at.isoformat(),
            }
            for log in logs
        ],
    }


# ------------------------------------------------------------------ #
#  GET /admin/users                                                    #
# ------------------------------------------------------------------ #

@router.get(
    "/users",
    response_model=UserListResponse,
    status_code=status.HTTP_200_OK,
    summary="List all users (sys_admin only)",
    description="Return a paginated list of all user accounts.",
)
def list_users(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    institution_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_sys_admin),
):
    query = db.query(User)

    if institution_id:
        query = query.filter(User.institution_id == institution_id)

    total = query.count()
    users = (
        query
        .order_by(User.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return UserListResponse(
        total=total,
        page=page,
        page_size=page_size,
        users=users,
    )


# ------------------------------------------------------------------ #
#  PATCH /admin/users/{user_id}/deactivate                            #
# ------------------------------------------------------------------ #

@router.patch(
    "/users/{user_id}/deactivate",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Deactivate a user account (sys_admin only)",
    description=(
        "Deactivate a user account. The account is not deleted — "
        "it is marked inactive so audit trail remains intact. "
        "The user will be unable to log in."
    ),
)
def deactivate_user(
    user_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_sys_admin),
):
    target = db.query(User).filter(User.id == user_id).first()

    if not target:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="User not found.")

    if target.id == current_user.id:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=400,
            detail="You cannot deactivate your own account.",
        )

    target.is_active = False
    db.commit()
    db.refresh(target)

    try:
        log = AuditLog.create(
            action=AuditAction.DEACTIVATE_USER,
            resource_type=ResourceType.USER,
            user_id=current_user.id,
            resource_id=str(target.id),
            success=True,
            ip_address=request.client.host if request.client else "unknown",
            endpoint=str(request.url.path),
            http_method=request.method,
        )
        db.add(log)
        db.commit()
    except Exception as e:
        logger.error(f"Audit log failed: {e}")

    return target

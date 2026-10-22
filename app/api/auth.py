import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.rbac import get_current_user, require_sys_admin
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    hash_password,
    verify_password,
)
from app.database import get_db
from app.models.audit import AuditAction, AuditLog, ResourceType
from app.models.user import User, UserRole
from app.schemas.user import (
    TokenRefreshRequest,
    TokenRefreshResponse,
    TokenResponse,
    UserCreate,
    UserLogin,
    UserResponse,
    UserRoleUpdate,
)
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
    # All responses from this router will include these in the docs
    responses={
        401: {"description": "Invalid or expired token"},
        422: {"description": "Validation error — check request body"},
    },
)


# ------------------------------------------------------------------ #
#  Helper — write audit log entry                                     #
# ------------------------------------------------------------------ #

def _write_audit_log(
    db: Session,
    action: AuditAction,
    request: Request,
    user_id=None,
    resource_id: str = None,
    success: bool = True,
    error_detail: str = None,
):
    """Write a single audit log entry and commit it immediately."""
    try:
        log = AuditLog.create(
            action=action,
            resource_type=ResourceType.AUTH,
            user_id=user_id,
            resource_id=resource_id,
            success=success,
            error_detail=error_detail,
            ip_address=_get_ip(request),
            user_agent=request.headers.get("user-agent", "")[:500],
            endpoint=str(request.url.path),
            http_method=request.method,
        )
        db.add(log)
        db.commit()
    except Exception as e:
        # Audit log failure must never break the main request
        logger.error(f"Failed to write audit log: {e}")
        db.rollback()


def _get_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ------------------------------------------------------------------ #
#  POST /auth/register                                                 #
# ------------------------------------------------------------------ #

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    description=(
        "Create a new researcher account. All new accounts are assigned "
        "the **researcher** role by default. An administrator must "
        "manually elevate accounts to institution_admin or sys_admin."
    ),
)
def register(
    user_in: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Register a new user.

    Steps:
        1. Check email is not already registered
        2. Hash the password
        3. Create the User record
        4. Write an audit log entry
        5. Return the new user (without password)
    """
        
        
    # ---- Step 1: Check email uniqueness --------------------------- #
    existing = db.query(User).filter(
        User.email == user_in.email
    ).first()

    if existing:
        # Do NOT reveal whether the email is registered — this
        # prevents user enumeration attacks where an attacker probes
        # which emails have accounts.
        # However for a portfolio/research tool a clear message is
        # acceptable. In a production consumer app, use a generic message.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists.",
        )

    # ---- Step 2: Hash the password -------------------------------- #
    # The plain text password is hashed here and then discarded.
    # It is never stored, logged, or passed further down the stack.
    hashed = hash_password(user_in.password)

    # ---- Step 3: Create the user ---------------------------------- #
    new_user = User(
        email=user_in.email,
        hashed_password=hashed,
        full_name=user_in.full_name,
        institution_id=user_in.institution_id,
        role=UserRole.RESEARCHER,   # always start as researcher
        is_active=True,
    )

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)   # reload from DB to get generated fields
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create user {user_in.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Account creation failed. Please try again.",
        )

    # ---- Step 4: Audit log --------------------------------------- #
    _write_audit_log(
        db=db,
        action=AuditAction.REGISTER,
        request=request,
        user_id=new_user.id,
        resource_id=str(new_user.id),
        success=True,
    )

    logger.info(f"New user registered: {new_user.email} ({new_user.id})")

    # ---- Step 5: Return the user --------------------------------- #
    # UserResponse schema excludes hashed_password automatically
    return new_user


# ------------------------------------------------------------------ #
#  POST /auth/login                                                    #
# ------------------------------------------------------------------ #

@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Log in and receive JWT tokens",
    description=(
        "Authenticate with email and password. Returns an **access token** "
        "(valid 30 minutes) and a **refresh token** (valid 7 days). "
        "Include the access token in the `Authorization: Bearer <token>` "
        "header on all subsequent requests."
    ),
)
def login(
    credentials: UserLogin,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Authenticate a user and issue JWT tokens.

    Steps:
        1. Look up the user by email
        2. Verify the password
        3. Check the account is active
        4. Create access + refresh tokens
        5. Update last_login_at timestamp
        6. Write an audit log entry
        7. Return tokens + user profile
    """

    # ---- Step 1: Look up user by email ---------------------------- #
    # Enforce strict rate limit on login — brute force protection
    from app.core.rate_limit import enforce_rate_limit
    enforce_rate_limit(request, identifier="auth")

    user = db.query(User).filter(
        User.email == credentials.email
    ).first()

    # ---- Step 2: Verify password ---------------------------------- #
    # IMPORTANT: We check both user existence AND password in the same
    # conditional and return the same error message for both cases.
    # This prevents user enumeration — an attacker cannot tell whether
    # an email is registered by comparing error messages.
    if not user or not verify_password(credentials.password, user.hashed_password):
        # Log the failed attempt — important for detecting brute force
        _write_audit_log(
            db=db,
            action=AuditAction.FAILED_LOGIN,
            request=request,
            user_id=user.id if user else None,
            success=False,
            error_detail=f"Failed login attempt for email: {credentials.email}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ---- Step 3: Check account is active -------------------------- #
    if not user.is_active:
        _write_audit_log(
            db=db,
            action=AuditAction.FAILED_LOGIN,
            request=request,
            user_id=user.id,
            success=False,
            error_detail="Login attempt on deactivated account.",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account has been deactivated. Contact your administrator.",
        )

    # ---- Step 4: Create tokens ------------------------------------ #
    access_token = create_access_token(
        user_id=str(user.id),
        role=user.role.value,
        institution_id=user.institution_id,
    )
    refresh_token = create_refresh_token(
        user_id=str(user.id),
    )

    # ---- Step 5: Update last login timestamp ---------------------- #
    try:
        user.last_login_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(user)
    except Exception as e:
        # Non-critical — don't fail the login if this update fails
        db.rollback()
        logger.warning(f"Failed to update last_login_at for {user.email}: {e}")

    # ---- Step 6: Audit log --------------------------------------- #
    _write_audit_log(
        db=db,
        action=AuditAction.LOGIN,
        request=request,
        user_id=user.id,
        resource_id=str(user.id),
        success=True,
    )

    logger.info(f"User logged in: {user.email} (role={user.role.value})")

    # ---- Step 7: Return tokens + user profile -------------------- #
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


# ------------------------------------------------------------------ #
#  POST /auth/refresh                                                  #
# ------------------------------------------------------------------ #

@router.post(
    "/refresh",
    response_model=TokenRefreshResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh an expired access token",
    description=(
        "Exchange a valid refresh token for a new access token. "
        "Use this when the access token expires (every 30 minutes) "
        "so the user does not need to log in again."
    ),
)
def refresh_token(
    token_in: TokenRefreshRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Issue a new access token using a valid refresh token.
    """

    # Validate the refresh token
    payload = decode_refresh_token(token_in.refresh_token)

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Look up the user
    from uuid import UUID
    user_id = UUID(payload.get("sub"))
    user = db.query(User).filter(User.id == user_id).first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or account deactivated.",
        )

    # Issue a fresh access token
    new_access_token = create_access_token(
        user_id=str(user.id),
        role=user.role.value,
        institution_id=user.institution_id,
    )

    _write_audit_log(
        db=db,
        action=AuditAction.TOKEN_REFRESH,
        request=request,
        user_id=user.id,
        success=True,
    )

    return TokenRefreshResponse(
        access_token=new_access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


# ------------------------------------------------------------------ #
#  POST /auth/logout                                                   #
# ------------------------------------------------------------------ #

@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Log out the current user",
    description=(
        "Log out and invalidate the current session. "
        "The client should discard both tokens after calling this endpoint."
    ),
)
def logout(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Log out the current user.

    Note on JWT logout: JWTs are stateless — the server cannot
    truly invalidate them. The correct approach is:
      1. Client discards the token immediately
      2. Short expiry (30 min) limits the damage window
      3. A Redis token blacklist (Phase 5) adds server-side revocation

    This endpoint records the logout in the audit log and returns
    a confirmation. The client is responsible for deleting the token.
    """
        # Blacklist the token in Redis so it cannot be reused
    from app.core.rate_limit import blacklist_token
    token = request.headers.get("authorization", "").replace("Bearer ", "")
    if token:
        blacklist_token(
            token,
            expires_in_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    _write_audit_log(
        db=db,
        action=AuditAction.LOGOUT,
        request=request,
        user_id=current_user.id,
        success=True,
    )

    logger.info(f"User logged out: {current_user.email}")

    return {
        "message": "Successfully logged out.",
        "detail": "Please discard your access and refresh tokens.",
    }


# ------------------------------------------------------------------ #
#  GET /auth/me                                                        #
# ------------------------------------------------------------------ #

@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current user profile",
    description="Return the profile of the currently authenticated user.",
)
def get_me(
    current_user: User = Depends(get_current_user),
):
    """
    Return the authenticated user's own profile.
    Useful for the client to display user info without
    storing it separately.
    """
    return current_user


# ------------------------------------------------------------------ #
#  PATCH /auth/users/{user_id}/role  (sys_admin only)                 #
# ------------------------------------------------------------------ #

@router.patch(
    "/users/{user_id}/role",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Update a user's role (sys_admin only)",
    description=(
        "Assign a new role to any user. "
        "Only **sys_admin** accounts can perform this action."
    ),
)
def update_user_role(
    user_id: str,
    role_in: UserRoleUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_sys_admin),
):
    """
    Change a user's role. Sys admin only.
    """
    from uuid import UUID

    try:
        target_id = UUID(user_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid user ID format.",
        )

    target_user = db.query(User).filter(User.id == target_id).first()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    old_role = target_user.role
    target_user.role = role_in.role

    try:
        db.commit()
        db.refresh(target_user)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update role.",
        )

    _write_audit_log(
        db=db,
        action=AuditAction.UPDATE_USER,
        request=request,
        user_id=current_user.id,
        resource_id=str(target_user.id),
        success=True,
        error_detail=f"Role changed from {old_role} to {role_in.role}",
    )

    logger.info(
        f"Role updated: {target_user.email} "
        f"{old_role} → {role_in.role} "
        f"by {current_user.email}"
    )

    return target_user
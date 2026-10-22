import logging
from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.database import get_db
from app.models.user import User, UserRole

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  Bearer token extractor                                              #
# ------------------------------------------------------------------ #

bearer_scheme = HTTPBearer(auto_error=False)


# ------------------------------------------------------------------ #
#  Core dependency — get_current_user()                               #
# ------------------------------------------------------------------ #

def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    FastAPI dependency that extracts and validates the JWT token,
    then returns the authenticated User ORM object.

    Raises HTTP 401 if:
        - No Authorization header is present
        - Token is blacklisted (user logged out)
        - Token is malformed, expired, or has an invalid signature
        - User ID in the token does not exist in the database
        - User account has been deactivated
    """

    # ---- Blacklist check (Redis) ---------------------------------- #
    # Must run before anything else — catches logged-out tokens
    if credentials is not None:
        from app.core.rate_limit import is_token_blacklisted
        if is_token_blacklisted(credentials.credentials):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked. Please log in again.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # ---- Step 1: Check the Authorization header exists ------------ #
    if credentials is None:
        logger.warning(
            f"Unauthenticated request to {request.url.path} "
            f"from {_get_client_ip(request)}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Include 'Authorization: Bearer <token>' header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ---- Step 2: Decode and validate the JWT ---------------------- #
    token = credentials.credentials
    payload = decode_access_token(token)

    if payload is None:
        logger.warning(
            f"Invalid token presented at {request.url.path} "
            f"from {_get_client_ip(request)}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ---- Step 3: Extract the user ID from the payload ------------- #
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload is malformed.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = UUID(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token contains an invalid user identifier.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ---- Step 4: Look up the user in the database ----------------- #
    user = db.query(User).filter(User.id == user_id).first()

    if user is None:
        logger.warning(
            f"Token references non-existent user {user_id} "
            f"at {request.url.path}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ---- Step 5: Confirm the account is active -------------------- #
    if not user.is_active:
        logger.warning(
            f"Deactivated user {user.email} attempted access "
            f"at {request.url.path}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account has been deactivated. Contact your administrator.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ---- Step 6: Return the user ---------------------------------- #
    return user


# ------------------------------------------------------------------ #
#  Optional auth — get_current_user_optional()                        #
# ------------------------------------------------------------------ #

def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """
    Like get_current_user() but returns None instead of raising 401
    when no token is present or the token is invalid.
    Use for endpoints that serve both public and authenticated users.
    """
    if credentials is None:
        return None

    payload = decode_access_token(credentials.credentials)
    if payload is None:
        return None

    user_id_str = payload.get("sub")
    if not user_id_str:
        return None

    try:
        user_id = UUID(user_id_str)
    except ValueError:
        return None

    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active:
        return None

    return user


# ------------------------------------------------------------------ #
#  Role-based access control — require_role()                         #
# ------------------------------------------------------------------ #

def require_role(*roles: UserRole):
    """
    Factory function that returns a FastAPI dependency enforcing
    role-based access. Pass the roles you want to permit.
    """
    def role_checker(
        request: Request,
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in roles:
            logger.warning(
                f"Access denied: user {current_user.email} "
                f"(role={current_user.role}) attempted to access "
                f"{request.url.path} which requires {[r.value for r in roles]}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Access denied. This endpoint requires one of: "
                    f"{', '.join(r.value for r in roles)}. "
                    f"Your role is: {current_user.role.value}."
                ),
            )
        return current_user

    return role_checker


# ------------------------------------------------------------------ #
#  Convenience shortcuts                                               #
# ------------------------------------------------------------------ #

def require_researcher(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> User:
    """Allows: researcher, institution_admin, sys_admin."""
    allowed = (
        UserRole.RESEARCHER,
        UserRole.INSTITUTION_ADMIN,
        UserRole.SYS_ADMIN,
    )
    if current_user.role not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Researcher access required.",
        )
    return current_user


def require_institution_admin(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> User:
    """Allows: institution_admin, sys_admin."""
    allowed = (
        UserRole.INSTITUTION_ADMIN,
        UserRole.SYS_ADMIN,
    )
    if current_user.role not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Institution administrator access required.",
        )
    return current_user


def require_sys_admin(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> User:
    """Allows: sys_admin only."""
    if current_user.role != UserRole.SYS_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="System administrator access required.",
        )
    return current_user


# ------------------------------------------------------------------ #
#  Institution ownership check                                        #
# ------------------------------------------------------------------ #

def verify_institution_access(
    current_user: User,
    resource_institution_id: Optional[str],
    is_public: bool = False,
) -> bool:
    """
    Check whether a user can access a resource owned by an institution.

    Rules:
        - sys_admin        → always allowed
        - is_public=True   → any authenticated user allowed
        - same institution → allowed
        - different inst.  → denied
    """
    if current_user.role == UserRole.SYS_ADMIN:
        return True
    if is_public:
        return True
    if resource_institution_id is None:
        return True
    return current_user.institution_id == resource_institution_id


# ------------------------------------------------------------------ #
#  Private helper                                                      #
# ------------------------------------------------------------------ #

def _get_client_ip(request: Request) -> str:
    """Extract real client IP, respecting X-Forwarded-For from Nginx."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
from datetime import datetime, timedelta, timezone
from typing import Optional
import logging

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import settings

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  Password hashing                                                    #
#                                                                      #
#  CryptContext manages the hashing algorithm for us.                 #
#  - scheme="bcrypt"  → use bcrypt algorithm                          #
#  - deprecated="auto" → automatically migrate old hashes if we       #
#    ever switch algorithms in the future                              #
#                                                                      #
#  bcrypt deliberately runs slowly (controlled by BCRYPT_ROUNDS       #
#  in config.py). This is intentional — it makes brute-force          #
#  attacks computationally expensive. At rounds=12, one hash          #
#  takes ~250ms. A normal user never notices. An attacker trying      #
#  millions of passwords absolutely does.                             #
# ------------------------------------------------------------------ #

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.BCRYPT_ROUNDS,
)


def hash_password(plain_password: str) -> str:
    """
    Hash a plain text password using bcrypt.

    NEVER store plain text passwords. Call this function when a user
    registers or changes their password, and store the result.

    Example:
        hashed = hash_password("MySecurePassword123!")
        # Store `hashed` in the database, discard the original
    """
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a stored bcrypt hash.

    Uses a timing-safe comparison internally — the comparison takes
    the same amount of time whether the password is correct or not.
    This prevents timing attacks where an attacker measures response
    time to guess characters of a password.

    Returns True if the password matches, False otherwise.

    Example:
        is_valid = verify_password("MySecurePassword123!", stored_hash)
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        # Log the error but never expose details to the caller
        logger.warning(f"Password verification error: {e}")
        return False


def is_password_strong(password: str) -> tuple[bool, str]:
    """
    Check if a password meets minimum security requirements.

    Returns a tuple of (is_valid: bool, reason: str).
    The reason is empty if the password is valid.

    Rules:
        - At least MIN_PASSWORD_LENGTH characters (default: 12)
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character

    Example:
        valid, reason = is_password_strong("weakpass")
        if not valid:
            raise HTTPException(400, detail=reason)
    """
    min_len = settings.MIN_PASSWORD_LENGTH

    if len(password) < min_len:
        return False, f"Password must be at least {min_len} characters long."

    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."

    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."

    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."

    special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
    if not any(c in special_chars for c in password):
        return False, "Password must contain at least one special character."

    return True, ""


# ------------------------------------------------------------------ #
#  JWT Token creation                                                  #
#                                                                      #
#  JWT (JSON Web Token) is the "key card" users get after logging in. #
#                                                                      #
#  Structure of a JWT:                                                 #
#    header.payload.signature                                          #
#                                                                      #
#  - header:    algorithm used (HS256)                                 #
#  - payload:   the data we store (user ID, role, expiry)             #
#  - signature: proves the token was created by us and not tampered   #
#                                                                      #
#  The payload is BASE64-encoded, not encrypted — anyone can          #
#  decode it. NEVER put sensitive data (passwords, PII) in a JWT.     #
#  The signature is what makes it secure — without our SECRET_KEY,    #
#  an attacker cannot create a valid signature.                        #
# ------------------------------------------------------------------ #

def create_access_token(
    user_id: str,
    role: str,
    institution_id: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a signed JWT access token for an authenticated user.

    The token contains:
        sub  — subject (user's UUID as a string)
        role — user's role (researcher / institution_admin / sys_admin)
        inst — institution ID (for RBAC filtering)
        exp  — expiry timestamp (default: 30 minutes from now)
        iat  — issued at timestamp
        type — token type flag ("access")

    Args:
        user_id:        The user's UUID as a string
        role:           The user's role string
        institution_id: Optional institution identifier
        expires_delta:  Optional custom expiry duration

    Returns:
        A signed JWT string to return to the client

    Example:
        token = create_access_token(
            user_id=str(user.id),
            role=user.role.value,
            institution_id=user.institution_id,
        )
    """
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta
        or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    payload = {
        "sub": user_id,           # subject — who this token belongs to
        "role": role,             # role — for RBAC checks
        "inst": institution_id,   # institution — for data scoping
        "exp": expire,            # expiry — token invalid after this
        "iat": now,               # issued at — when token was created
        "type": "access",         # type flag — distinguishes from refresh
    }

    return jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )


def create_refresh_token(
    user_id: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a longer-lived refresh token.

    Refresh tokens contain minimal data — just the user ID and type.
    They are used to obtain a new access token without re-entering
    credentials. They should be stored securely by the client
    (httpOnly cookie or secure storage).

    Default expiry: 7 days (configurable via REFRESH_TOKEN_EXPIRE_DAYS)

    Args:
        user_id:      The user's UUID as a string
        expires_delta: Optional custom expiry duration

    Returns:
        A signed JWT refresh token string
    """
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta
        or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )

    payload = {
        "sub": user_id,
        "exp": expire,
        "iat": now,
        "type": "refresh",    # type flag — RBAC module rejects this
                              # if presented as an access token
    }

    return jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )


# ------------------------------------------------------------------ #
#  JWT Token validation                                                #
# ------------------------------------------------------------------ #

def decode_access_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT access token.

    Performs three checks automatically:
        1. Signature — was this token signed with our SECRET_KEY?
        2. Expiry    — has the token expired?
        3. Type      — is this actually an access token (not refresh)?

    Returns the decoded payload dict if valid, None if invalid.
    Never raises exceptions to callers — invalid tokens return None.

    The RBAC module (rbac.py) calls this and raises HTTP 401 if
    None is returned.

    Example:
        payload = decode_access_token(token_string)
        if payload is None:
            raise HTTPException(401, "Invalid or expired token")
        user_id = payload["sub"]
        role = payload["role"]
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )

        # Reject refresh tokens presented as access tokens
        if payload.get("type") != "access":
            logger.warning("Refresh token presented as access token — rejected.")
            return None

        # Confirm required fields are present
        if not payload.get("sub"):
            logger.warning("JWT missing 'sub' field.")
            return None

        return payload

    except JWTError as e:
        # JWTError covers: expired tokens, bad signature, malformed tokens
        logger.debug(f"JWT validation failed: {e}")
        return None

    except Exception as e:
        logger.error(f"Unexpected error decoding token: {e}")
        return None


def decode_refresh_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT refresh token.

    Same as decode_access_token but accepts type="refresh" only.
    Used by the token refresh endpoint.

    Returns the decoded payload dict if valid, None if invalid.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )

        if payload.get("type") != "refresh":
            logger.warning("Access token presented as refresh token — rejected.")
            return None

        if not payload.get("sub"):
            return None

        return payload

    except JWTError as e:
        logger.debug(f"Refresh token validation failed: {e}")
        return None

    except Exception as e:
        logger.error(f"Unexpected error decoding refresh token: {e}")
        return None


def extract_token_data(payload: dict) -> dict:
    """
    Pull the important fields out of a decoded JWT payload
    into a clean dictionary.

    Args:
        payload: The decoded JWT payload from decode_access_token()

    Returns:
        Dict with keys: user_id, role, institution_id

    Example:
        payload = decode_access_token(token)
        data = extract_token_data(payload)
        print(data["user_id"])   # "550e8400-e29b-41d4-a716-..."
        print(data["role"])      # "researcher"
    """
    return {
        "user_id": payload.get("sub"),
        "role": payload.get("role"),
        "institution_id": payload.get("inst"),
    }
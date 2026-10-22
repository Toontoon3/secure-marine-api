import logging
import time
from typing import Optional

import redis
from fastapi import HTTPException, Request, status

from app.config import settings

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  Redis connection                                                    #
#                                                                      #
#  A single Redis client instance shared across all requests.         #
#  decode_responses=True means Redis returns strings instead of       #
#  bytes — cleaner to work with in Python.                            #
# ------------------------------------------------------------------ #

def _get_redis_client() -> Optional[redis.Redis]:
    """
    Create and return a Redis client.
    Returns None if Redis is unreachable — rate limiting
    degrades gracefully rather than taking down the API.
    """
    try:
        client = redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        client.ping()   # confirm connection is alive
        return client
    except Exception as e:
        logger.warning(f"Redis unavailable — rate limiting disabled: {e}")
        return None


redis_client = _get_redis_client()


# ------------------------------------------------------------------ #
#  Token blacklist                                                     #
#                                                                      #
#  When a user logs out, their token is added to this blacklist.      #
#  Every protected request checks the blacklist before proceeding.    #
#  Tokens are stored with a TTL equal to their remaining lifetime     #
#  so Redis auto-expires them — no manual cleanup needed.             #
# ------------------------------------------------------------------ #

BLACKLIST_PREFIX = "blacklist:"


def blacklist_token(token: str, expires_in_seconds: int) -> bool:
    """
    Add a JWT token to the Redis blacklist.

    Args:
        token:              The raw JWT string to blacklist
        expires_in_seconds: How long to keep it in Redis
                            (should match the token's remaining lifetime)

    Returns:
        True if successfully blacklisted, False if Redis is down.

    Usage in logout endpoint:
        from app.core.rate_limit import blacklist_token
        blacklist_token(token, expires_in_seconds=1800)
    """
    if redis_client is None:
        logger.warning("Cannot blacklist token — Redis unavailable.")
        return False
    try:
        key = f"{BLACKLIST_PREFIX}{token}"
        redis_client.setex(key, expires_in_seconds, "blacklisted")
        return True
    except Exception as e:
        logger.error(f"Failed to blacklist token: {e}")
        return False


def is_token_blacklisted(token: str) -> bool:
    """
    Check if a JWT token has been blacklisted (logged out).

    Returns True if the token is blacklisted, False otherwise.
    Returns False if Redis is down (fail open — prefer availability).

    Usage in rbac.py get_current_user():
        from app.core.rate_limit import is_token_blacklisted
        if is_token_blacklisted(credentials.credentials):
            raise HTTPException(401, "Token has been revoked.")
    """
    if redis_client is None:
        return False
    try:
        key = f"{BLACKLIST_PREFIX}{token}"
        return redis_client.exists(key) > 0
    except Exception as e:
        logger.error(f"Failed to check token blacklist: {e}")
        return False


# ------------------------------------------------------------------ #
#  Rate limiter                                                        #
#                                                                      #
#  Sliding window rate limiter using Redis.                           #
#                                                                      #
#  How it works:                                                       #
#    - Each request increments a counter stored in Redis              #
#    - The counter key includes the IP + endpoint category            #
#    - The key expires after RATE_LIMIT_WINDOW_SECONDS automatically  #
#    - If the counter exceeds the limit, return 429                   #
#                                                                      #
#  Two tiers:                                                          #
#    - General:  100 requests / 60 seconds per IP                     #
#    - Auth:      10 requests / 60 seconds per IP (brute force guard) #
# ------------------------------------------------------------------ #

RATE_PREFIX = "rate:"


def _get_client_ip(request: Request) -> str:
    """Extract real client IP, respecting X-Forwarded-For from Nginx."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check_rate_limit(
    request: Request,
    limit: int,
    window_seconds: int,
    identifier: str = "",
) -> tuple[bool, int, int]:
    """
    Check and increment the rate limit counter for this request.

    Args:
        request:        The incoming HTTP request
        limit:          Maximum requests allowed in the window
        window_seconds: The window duration in seconds
        identifier:     Extra string to namespace the key
                        (e.g. "auth" for login endpoints)

    Returns:
        Tuple of (is_allowed, current_count, remaining)
        - is_allowed:    True if request is within the limit
        - current_count: How many requests have been made
        - remaining:     How many requests are left in this window

    If Redis is down, always returns (True, 0, limit) — fail open.
    """
    if redis_client is None:
        return True, 0, limit

    ip = _get_client_ip(request)
    window_key = int(time.time() / window_seconds)
    key = f"{RATE_PREFIX}{identifier}:{ip}:{window_key}"

    try:
        pipe = redis_client.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds)
        results = pipe.execute()
        current_count = results[0]

        is_allowed = current_count <= limit
        remaining = max(0, limit - current_count)
        return is_allowed, current_count, remaining

    except Exception as e:
        logger.error(f"Rate limit check failed: {e}")
        return True, 0, limit     # fail open if Redis errors


def enforce_rate_limit(
    request: Request,
    limit: Optional[int] = None,
    window_seconds: Optional[int] = None,
    identifier: str = "",
) -> None:
    """
    Enforce rate limiting on a request. Raises HTTP 429 if exceeded.

    This is the function you call directly inside endpoints or
    as a FastAPI dependency.

    Args:
        request:        The incoming request
        limit:          Override the default limit from config
        window_seconds: Override the default window from config
        identifier:     Namespace — use "auth" for login endpoints

    Raises:
        HTTP 429 Too Many Requests if the limit is exceeded.

    Usage as a direct call inside an endpoint:
        enforce_rate_limit(request, identifier="auth")

    Usage as a FastAPI dependency:
        @router.post("/login")
        def login(request: Request, ...):
            enforce_rate_limit(request, identifier="auth")
            ...
    """
    _limit = limit or settings.RATE_LIMIT_REQUESTS
    _window = window_seconds or settings.RATE_LIMIT_WINDOW_SECONDS

    # Use stricter limits for auth endpoints
    if identifier == "auth":
        _limit = settings.AUTH_RATE_LIMIT_REQUESTS
        _window = settings.AUTH_RATE_LIMIT_WINDOW_SECONDS

    is_allowed, current_count, remaining = check_rate_limit(
        request, _limit, _window, identifier
    )

    if not is_allowed:
        ip = _get_client_ip(request)
        logger.warning(
            f"Rate limit exceeded: IP={ip} "
            f"path={request.url.path} "
            f"count={current_count} limit={_limit}"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Too many requests. "
                f"Limit: {_limit} requests per {_window} seconds. "
                f"Please wait before trying again."
            ),
            headers={
                "Retry-After": str(_window),
                "X-RateLimit-Limit": str(_limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(
                    int(time.time() / _window + 1) * _window
                ),
            },
        )

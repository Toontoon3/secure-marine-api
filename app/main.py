import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import check_database_connection, create_tables

# ------------------------------------------------------------------ #
#  Logging setup                                                       #
#                                                                      #
#  Configure logging before anything else so every module that        #
#  runs during startup already has a logger available.                #
# ------------------------------------------------------------------ #

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  Lifespan — startup and shutdown events                             #
#                                                                      #
#  The lifespan context manager replaces the old @app.on_event        #
#  decorator pattern. Everything before `yield` runs on startup,      #
#  everything after runs on shutdown.                                  #
# ------------------------------------------------------------------ #

@asynccontextmanager
async def lifespan(app: FastAPI):
    # ---- STARTUP -------------------------------------------------- #
    logger.info("=" * 60)
    logger.info(f"  {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"  Environment : {settings.ENVIRONMENT}")
    logger.info(f"  Debug mode  : {settings.DEBUG}")
    logger.info("=" * 60)

    # Verify database connection is reachable
    logger.info("Checking database connection...")
    if check_database_connection():
        logger.info("Database connection OK.")
    else:
        logger.error(
            "Cannot reach the database. "
            "Check DATABASE_URL in your .env file and confirm "
            "PostgreSQL is running (docker ps)."
        )
        # We do not exit here — the app starts anyway so you can
        # see the error in logs. In production you may want to
        # raise SystemExit(1) to prevent a broken deployment.

    # In development, create tables automatically if they don't exist.
    # In production, always use: alembic upgrade head
    if settings.is_development:
        logger.info("Development mode — verifying tables exist...")
        create_tables()

    logger.info("Startup complete. API is ready.")
    logger.info(f"Swagger UI available at: http://localhost:8000/docs")
    logger.info(f"ReDoc available at     : http://localhost:8000/redoc")

    yield  # <-- application runs here

    # ---- SHUTDOWN ------------------------------------------------- #
    logger.info("Shutting down Secure Marine Data API...")
    logger.info("Shutdown complete.")


# ------------------------------------------------------------------ #
#  FastAPI application instance                                        #
# ------------------------------------------------------------------ #

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    lifespan=lifespan,

    # Swagger UI and ReDoc are only available in non-production.
    # In production, set ENVIRONMENT=production in .env to disable
    # public API documentation exposure.
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
    openapi_url="/openapi.json" if not settings.is_production else None,

    # Contact and licence info shown in Swagger UI
    contact={
        "name": "Secure Marine Data API",
        "url": "https://github.com/yourusername/secure-marine-api",
    },
    license_info={
        "name": "MIT",
    },
    # Group endpoints by tag in Swagger UI
    openapi_tags=[
        {
            "name": "Authentication",
            "description": (
                "Register, login, token refresh, and logout. "
                "All protected endpoints require a Bearer token "
                "from /auth/login."
            ),
        },
        {
            "name": "Datasets",
            "description": (
                "Upload, download, and list oceanographic datasets. "
                "Access is controlled by role and institution membership."
            ),
        },
        {
            "name": "Admin",
            "description": (
                "System administration endpoints. "
                "Restricted to sys_admin role."
            ),
        },
        {
            "name": "Health",
            "description": "Service health and readiness checks.",
        },
    ],
)


# ------------------------------------------------------------------ #
#  Middleware                                                          #
#                                                                      #
#  Middleware runs on every request/response automatically.            #
#  Order matters — middleware is applied in reverse registration       #
#  order (last added = first to run on request).                      #
# ------------------------------------------------------------------ #

# ---- CORS --------------------------------------------------------- #
# Cross-Origin Resource Sharing — controls which domains can call
# this API from a browser. Browsers enforce this; Postman does not.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)


# ---- Security headers --------------------------------------------- #
# Inject security headers into every response.
# These protect against common browser-based attacks.
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=()"
    )
    # Only send HSTS on HTTPS connections
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


# ---- Request timing ----------------------------------------------- #
# Log how long every request takes. Useful for spotting slow endpoints.
@app.middleware("http")
async def log_request_timing(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000
    logger.info(
        f"{request.method} {request.url.path} "
        f"→ {response.status_code} "
        f"({duration_ms:.1f}ms)"
    )
    return response


# ------------------------------------------------------------------ #
#  Global exception handlers                                          #
#                                                                      #
#  Catch unhandled exceptions and return clean JSON responses         #
#  instead of raw Python tracebacks. Never expose stack traces        #
#  to API clients — they reveal internal structure to attackers.      #
# ------------------------------------------------------------------ #

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "error": "Not found",
            "detail": f"The path '{request.url.path}' does not exist.",
            "status_code": 404,
        },
    )


@app.exception_handler(405)
async def method_not_allowed_handler(request: Request, exc):
    return JSONResponse(
        status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
        content={
            "error": "Method not allowed",
            "detail": (
                f"{request.method} is not allowed on '{request.url.path}'."
            ),
            "status_code": 405,
        },
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    logger.error(
        f"Unhandled exception on {request.method} {request.url.path}: "
        f"{exc}",
        exc_info=True,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "detail": (
                "An unexpected error occurred. "
                "The incident has been logged."
            ),
            "status_code": 500,
        },
    )


# ------------------------------------------------------------------ #
#  Routers                                                             #
#                                                                      #
#  Each router is a separate file in app/api/.                        #
#  Importing and including them here wires their endpoints into       #
#  the main application.                                              #
# ------------------------------------------------------------------ #

from app.api.auth import router as auth_router
app.include_router(auth_router)

# Dataset and admin routers will be added in Phase 4.
# Uncomment these lines when you have created those files:
#
from app.api.datasets import router as datasets_router
app.include_router(datasets_router)

from app.api.admin import router as admin_router
app.include_router(admin_router)


# ------------------------------------------------------------------ #
#  Health endpoints                                                    #
#                                                                      #
#  /health  — basic liveness check (is the process running?)          #
#  /ready   — readiness check (can it serve traffic?)                 #
#                                                                      #
#  Deployment platforms like Render and Railway ping /health to       #
#  know whether to route traffic to this instance.                    #
# ------------------------------------------------------------------ #

@app.get(
    "/health",
    tags=["Health"],
    summary="Liveness check",
    description="Returns 200 if the application process is running.",
)
def health_check():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
    }


@app.get(
    "/ready",
    tags=["Health"],
    summary="Readiness check",
    description=(
        "Returns 200 if the application is ready to serve traffic "
        "(database reachable). Returns 503 if not ready."
    ),
)
def readiness_check():
    db_ok = check_database_connection()

    if not db_ok:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "not ready",
                "database": "unreachable",
                "detail": "Service is not ready to accept traffic.",
            },
        )

    return {
        "status": "ready",
        "database": "connected",
    }


# ------------------------------------------------------------------ #
#  Root endpoint                                                       #
# ------------------------------------------------------------------ #

@app.get(
    "/",
    tags=["Health"],
    summary="API root",
    include_in_schema=False,   # hide from Swagger docs
)
def root():
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/health",
        "message": (
            "Secure REST API for exchanging oceanographic research data. "
            "See /docs for the full API reference."
        ),
    }
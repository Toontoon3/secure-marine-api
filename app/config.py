from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from typing import List
import secrets


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables / .env file.
    All values can be overridden by setting the corresponding environment
    variable. Pydantic reads the .env file automatically.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",          # silently ignore unknown env vars
    )

    # ------------------------------------------------------------------ #
    #  Application                                                         #
    # ------------------------------------------------------------------ #
    APP_NAME: str = "Secure Marine Data API"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = (
        "Hardened REST API for secure exchange of oceanographic research "
        "data between marine institutions."
    )
    ENVIRONMENT: str = "development"   # development | production
    DEBUG: bool = False

    # ------------------------------------------------------------------ #
    #  Security — JWT                                                      #
    # ------------------------------------------------------------------ #
    SECRET_KEY: str = secrets.token_hex(32)   # overridden in .env
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ------------------------------------------------------------------ #
    #  Security — Passwords                                                #
    # ------------------------------------------------------------------ #
    BCRYPT_ROUNDS: int = 12        # cost factor — higher = slower = safer
    MIN_PASSWORD_LENGTH: int = 12  # enforced at schema level

    # ------------------------------------------------------------------ #
    #  Database — PostgreSQL                                               #
    # ------------------------------------------------------------------ #
    DATABASE_URL: str = (
        "postgresql://marineuser:marinepass@localhost/marineapi"
    )
    DB_POOL_SIZE: int = 5          # number of persistent connections
    DB_MAX_OVERFLOW: int = 10      # extra connections allowed under load
    DB_POOL_TIMEOUT: int = 30      # seconds to wait for a connection
    DB_ECHO: bool = False          # set True to log all SQL (dev only)

    # ------------------------------------------------------------------ #
    #  Cache — Redis                                                       #
    # ------------------------------------------------------------------ #
    REDIS_URL: str = "redis://localhost:6379/0"

    # ------------------------------------------------------------------ #
    #  Rate limiting                                                       #
    # ------------------------------------------------------------------ #
    RATE_LIMIT_REQUESTS: int = 100    # requests allowed per window
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    AUTH_RATE_LIMIT_REQUESTS: int = 10   # stricter limit on /auth/login
    AUTH_RATE_LIMIT_WINDOW_SECONDS: int = 60

    # ------------------------------------------------------------------ #
    #  File uploads                                                        #
    # ------------------------------------------------------------------ #
    UPLOAD_DIR: str = "uploads"
    MAX_UPLOAD_SIZE_MB: int = 50
    ALLOWED_MIME_TYPES: List[str] = [
        "text/csv",
        "application/json",
        "application/x-netcdf",
        "application/octet-stream",   # some NetCDF files use this
    ]
    ALLOWED_EXTENSIONS: List[str] = [".csv", ".json", ".nc", ".cdf"]

    # ------------------------------------------------------------------ #
    #  CORS — origins allowed to call this API                            #
    # ------------------------------------------------------------------ #
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",   # local frontend dev
        "http://localhost:8080",
    ]

    # ------------------------------------------------------------------ #
    #  Derived / computed properties                                       #
    # ------------------------------------------------------------------ #
    @property
    def max_upload_size_bytes(self) -> int:
        """MAX_UPLOAD_SIZE_MB converted to bytes for use in endpoints."""
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT.lower() == "development"

    # ------------------------------------------------------------------ #
    #  Validators                                                          #
    # ------------------------------------------------------------------ #
    @field_validator("SECRET_KEY")
    @classmethod
    def secret_key_must_be_strong(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError(
                "SECRET_KEY must be at least 32 characters long. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        return v

    @field_validator("ENVIRONMENT")
    @classmethod
    def environment_must_be_valid(cls, v: str) -> str:
        allowed = {"development", "production", "testing"}
        if v.lower() not in allowed:
            raise ValueError(
                f"ENVIRONMENT must be one of: {', '.join(allowed)}"
            )
        return v.lower()

    @field_validator("BCRYPT_ROUNDS")
    @classmethod
    def bcrypt_rounds_must_be_safe(cls, v: int) -> int:
        if v < 10:
            raise ValueError(
                "BCRYPT_ROUNDS must be at least 10. "
                "Lower values are not secure enough for production."
            )
        return v


# ------------------------------------------------------------------ #
#  Singleton — import this instance everywhere in the app             #
# ------------------------------------------------------------------ #
settings = Settings()
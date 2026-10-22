import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

from app.models.user import UserRole
from app.core.security import is_password_strong


# ------------------------------------------------------------------ #
#  A note on Pydantic schemas vs ORM models                           #
#                                                                      #
#  ORM models  (app/models/)   → define database tables               #
#  Pydantic schemas (app/schemas/) → define API request/response shape #
#                                                                      #
#  They are kept separate deliberately:                                #
#  - Your ORM User model has hashed_password — never expose that      #
#  - Your response schemas only include safe fields                    #
#  - Your request schemas validate input before it touches the DB     #
# ------------------------------------------------------------------ #


# ------------------------------------------------------------------ #
#  Shared base                                                         #
# ------------------------------------------------------------------ #

class UserBase(BaseModel):
    """
    Fields shared between request and response schemas.
    All other schemas inherit from this.
    """
    email: EmailStr = Field(
        ...,
        description="User's email address. Must be unique in the system.",
        examples=["researcher@marine-institute.ie"],
    )
    full_name: Optional[str] = Field(
        None,
        min_length=2,
        max_length=255,
        description="User's full name.",
        examples=["Dr. Aoife Murphy"],
    )
    institution_id: Optional[str] = Field(
        None,
        max_length=100,
        description="Identifier for the user's institution.",
        examples=["marine-institute-ireland", "nmci-cork", "ucc-marei"],
    )


# ------------------------------------------------------------------ #
#  Request schemas — what the API accepts                             #
# ------------------------------------------------------------------ #

class UserCreate(UserBase):
    """
    Schema for POST /auth/register

    What the client sends when creating a new account.
    The password field exists ONLY in this schema — it is validated
    here and then hashed in the auth endpoint. It never appears
    in any response schema.
    """
    password: str = Field(
        ...,
        min_length=12,
        max_length=128,
        description=(
            "Password — minimum 12 characters, must include uppercase, "
            "lowercase, number, and special character."
        ),
        examples=["M@rineSecure2024!"],
    )

    @field_validator("password")
    @classmethod
    def password_must_be_strong(cls, v: str) -> str:
        """
        Enforce password strength policy defined in security.py.
        Returns a clear error message explaining exactly what is missing.
        """
        is_valid, reason = is_password_strong(v)
        if not is_valid:
            raise ValueError(reason)
        return v

    @field_validator("email")
    @classmethod
    def email_must_be_lowercase(cls, v: str) -> str:
        """
        Normalise emails to lowercase so 'User@Example.com'
        and 'user@example.com' are treated as the same address.
        """
        return v.lower().strip()

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "researcher@marine-institute.ie",
                "password": "M@rineSecure2024!",
                "full_name": "Dr. Aoife Murphy",
                "institution_id": "marine-institute-ireland",
            }
        }
    }


class UserLogin(BaseModel):
    """
    Schema for POST /auth/login

    Separate from UserCreate — login only needs email and password,
    not the other registration fields.
    """
    email: EmailStr = Field(
        ...,
        examples=["researcher@marine-institute.ie"],
    )
    password: str = Field(
        ...,
        min_length=1,      # minimal validation — detailed check is
        max_length=128,    # done by verify_password() in the endpoint
        examples=["M@rineSecure2024!"],
    )

    @field_validator("email")
    @classmethod
    def email_must_be_lowercase(cls, v: str) -> str:
        return v.lower().strip()

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "researcher@marine-institute.ie",
                "password": "M@rineSecure2024!",
            }
        }
    }


class UserUpdate(BaseModel):
    """
    Schema for PATCH /users/{user_id}

    All fields are optional — only send what needs to change.
    Cannot change email or password through this schema
    (those need dedicated endpoints with extra verification).
    """
    full_name: Optional[str] = Field(
        None,
        min_length=2,
        max_length=255,
    )
    institution_id: Optional[str] = Field(
        None,
        max_length=100,
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "full_name": "Dr. Aoife Murphy",
                "institution_id": "nmci-cork",
            }
        }
    }


# ------------------------------------------------------------------ #
#  Response schemas — what the API returns                            #
#                                                                      #
#  IMPORTANT: hashed_password is NEVER included in any response       #
#  schema. Pydantic will only serialise fields that are explicitly    #
#  declared here.                                                      #
# ------------------------------------------------------------------ #

class UserResponse(UserBase):
    """
    Schema for any endpoint that returns a user object.

    Safe to return — contains no sensitive fields.
    hashed_password is deliberately omitted.
    """
    id: uuid.UUID = Field(
        ...,
        description="User's unique identifier.",
    )
    role: UserRole = Field(
        ...,
        description="User's access role.",
    )
    is_active: bool = Field(
        ...,
        description="Whether the account is active.",
    )
    created_at: datetime = Field(
        ...,
        description="When the account was created.",
    )
    last_login_at: Optional[datetime] = Field(
        None,
        description="When the user last logged in.",
    )

    # model_config tells Pydantic to read data from ORM objects
    # (SQLAlchemy model instances), not just plain dicts.
    # Without this, UserResponse(user_orm_object) would fail.
    model_config = {
        "from_attributes": True,    # replaces orm_mode=True in Pydantic v1
        "json_schema_extra": {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "email": "researcher@marine-institute.ie",
                "full_name": "Dr. Aoife Murphy",
                "institution_id": "marine-institute-ireland",
                "role": "researcher",
                "is_active": True,
                "created_at": "2024-01-15T10:30:00Z",
                "last_login_at": "2024-01-20T09:15:00Z",
            }
        }
    }


class UserSummary(BaseModel):
    """
    Minimal user info — used when embedding user data inside
    other responses (e.g. showing who uploaded a dataset).
    Only exposes the absolute minimum needed.
    """
    id: uuid.UUID
    full_name: Optional[str]
    institution_id: Optional[str]
    role: UserRole

    model_config = {"from_attributes": True}


# ------------------------------------------------------------------ #
#  Token schemas — login response                                     #
# ------------------------------------------------------------------ #

class TokenResponse(BaseModel):
    """
    Schema for the response from POST /auth/login

    What the client receives after a successful login.
    The client must store access_token and send it in the
    Authorization header on every subsequent request:

        Authorization: Bearer <access_token>

    The refresh_token should be stored securely and used to
    get a new access_token when it expires (every 30 minutes).
    """
    access_token: str = Field(
        ...,
        description="JWT access token. Include in Authorization: Bearer header.",
    )
    refresh_token: str = Field(
        ...,
        description="JWT refresh token. Use to get a new access token.",
    )
    token_type: str = Field(
        default="bearer",
        description="Always 'bearer'. Required by OAuth2 spec.",
    )
    expires_in: int = Field(
        ...,
        description="Access token lifetime in seconds.",
    )
    user: UserResponse = Field(
        ...,
        description="The authenticated user's profile.",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 1800,
                "user": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "email": "researcher@marine-institute.ie",
                    "full_name": "Dr. Aoife Murphy",
                    "institution_id": "marine-institute-ireland",
                    "role": "researcher",
                    "is_active": True,
                    "created_at": "2024-01-15T10:30:00Z",
                    "last_login_at": "2024-01-20T09:15:00Z",
                }
            }
        }
    }


class TokenRefreshRequest(BaseModel):
    """
    Schema for POST /auth/refresh

    Client sends their refresh token to get a new access token.
    """
    refresh_token: str = Field(
        ...,
        description="A valid refresh token obtained from /auth/login.",
    )


class TokenRefreshResponse(BaseModel):
    """
    Schema for the response from POST /auth/refresh
    """
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# ------------------------------------------------------------------ #
#  Admin schemas                                                       #
# ------------------------------------------------------------------ #

class UserRoleUpdate(BaseModel):
    """
    Schema for PATCH /admin/users/{user_id}/role
    Only sys_admin can use this endpoint.
    """
    role: UserRole = Field(
        ...,
        description="The new role to assign to the user.",
    )

    model_config = {
        "json_schema_extra": {
            "example": {"role": "institution_admin"}
        }
    }


class UserListResponse(BaseModel):
    """
    Schema for paginated user list responses.
    """
    total: int = Field(..., description="Total number of users matching the query.")
    page: int = Field(..., description="Current page number.")
    page_size: int = Field(..., description="Number of results per page.")
    users: list[UserResponse]
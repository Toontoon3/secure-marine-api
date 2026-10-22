import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    Boolean, DateTime, Enum, String, func
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


# ------------------------------------------------------------------ #
#  Role enum                                                           #
#                                                                      #
#  Three roles with a strict hierarchy:                                #
#    researcher        — can upload/download their institution's data  #
#    institution_admin — manages researchers in their institution      #
#    sys_admin         — full access to everything                     #
# ------------------------------------------------------------------ #

class UserRole(str, PyEnum):
    RESEARCHER        = "researcher"
    INSTITUTION_ADMIN = "institution_admin"
    SYS_ADMIN         = "sys_admin"


# ------------------------------------------------------------------ #
#  User model                                                          #
# ------------------------------------------------------------------ #

class User(Base):
    __tablename__ = "users"

    # Primary key — UUID instead of integer so IDs are not guessable
    # and do not leak how many users exist in the system
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # Authentication fields
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,          # fast lookup on login
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        # NOTE: this column stores the bcrypt hash — NEVER the plain
        # text password. The password is hashed in core/security.py
        # before it ever reaches this model.
    )

    # Profile fields
    full_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    institution_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True,          # fast lookup of all users in an institution
    )

    # Access control
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole),
        nullable=False,
        default=UserRole.RESEARCHER,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        # Set to False instead of deleting users — preserves audit trail
    )

    # Timestamps — set automatically by the database
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ---------------------------------------------------------------- #
    #  Relationships                                                     #
    # ---------------------------------------------------------------- #

    # One user can upload many datasets
    datasets: Mapped[list["Dataset"]] = relationship(
        "Dataset",
        back_populates="uploader",
        lazy="select",
    )

    # One user can generate many audit log entries
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="user",
        lazy="select",
    )

    # ---------------------------------------------------------------- #
    #  Helpers                                                           #
    # ---------------------------------------------------------------- #

    def __repr__(self) -> str:
        return (
            f"<User id={self.id} email={self.email} role={self.role}>"
        )

    @property
    def is_admin(self) -> bool:
        """True for both institution_admin and sys_admin roles."""
        return self.role in (
            UserRole.INSTITUTION_ADMIN,
            UserRole.SYS_ADMIN,
        )

    @property
    def is_sys_admin(self) -> bool:
        return self.role == UserRole.SYS_ADMIN
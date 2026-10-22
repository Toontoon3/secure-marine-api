import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    Boolean, DateTime, Enum, ForeignKey,
    String, Text, func
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


# ------------------------------------------------------------------ #
#  Action enum                                                         #
#                                                                      #
#  Every meaningful action in the system has a named constant.        #
#  This makes audit log queries precise — you can filter for all      #
#  DOWNLOAD events, or all FAILED_LOGIN events, without string        #
#  matching.                                                           #
# ------------------------------------------------------------------ #

class AuditAction(str, PyEnum):
    # Authentication events
    REGISTER        = "REGISTER"
    LOGIN           = "LOGIN"
    LOGOUT          = "LOGOUT"
    FAILED_LOGIN    = "FAILED_LOGIN"
    TOKEN_REFRESH   = "TOKEN_REFRESH"

    # Dataset events
    UPLOAD          = "UPLOAD"
    DOWNLOAD        = "DOWNLOAD"
    DELETE_DATASET  = "DELETE_DATASET"
    VIEW_METADATA   = "VIEW_METADATA"
    LIST_DATASETS   = "LIST_DATASETS"

    # Admin events
    CREATE_USER     = "CREATE_USER"
    UPDATE_USER     = "UPDATE_USER"
    DEACTIVATE_USER = "DEACTIVATE_USER"
    VIEW_AUDIT_LOGS = "VIEW_AUDIT_LOGS"

    # Security events — logged automatically by middleware
    RATE_LIMITED    = "RATE_LIMITED"
    UNAUTHORISED    = "UNAUTHORISED"
    FORBIDDEN       = "FORBIDDEN"


# ------------------------------------------------------------------ #
#  Resource type enum                                                  #
#                                                                      #
#  What kind of object was the action performed on?                   #
# ------------------------------------------------------------------ #

class ResourceType(str, PyEnum):
    USER        = "user"
    DATASET     = "dataset"
    AUTH        = "auth"
    SYSTEM      = "system"


# ------------------------------------------------------------------ #
#  AuditLog model                                                      #
#                                                                      #
#  This table is append-only. Rows are never updated or deleted.      #
#  Every write is a permanent record. This is the security            #
#  foundation — it lets you answer "who did what, when, and           #
#  did it succeed?" after any incident.                                #
# ------------------------------------------------------------------ #

class AuditLog(Base):
    __tablename__ = "audit_logs"

    # Primary key — UUID, ordered by created_at for queries
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Who performed the action
    # Nullable because failed logins may not have a valid user_id yet
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        # SET NULL: if a user is deleted, keep the log but clear the FK.
        # The audit record remains — we just lose the FK reference.
        nullable=True,
        index=True,
    )

    # What was done
    action: Mapped[AuditAction] = mapped_column(
        Enum(AuditAction),
        nullable=False,
        index=True,
    )

    # What it was done to
    resource_type: Mapped[ResourceType] = mapped_column(
        Enum(ResourceType),
        nullable=False,
        index=True,
    )
    resource_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        # The ID of the affected object, e.g. the dataset UUID or user UUID
        # Stored as string to handle any ID format
    )

    # Outcome
    success: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        # False for failed logins, permission denials, rate limit hits
    )
    error_detail: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        # Human-readable reason for failure — never include sensitive data
        # e.g. "Insufficient role: researcher cannot access admin endpoints"
    )

    # Request context — critical for incident investigation
    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        # 45 chars covers full IPv6 addresses
        index=True,
    )
    user_agent: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        # Browser/client identifier — useful for detecting automated attacks
    )
    endpoint: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        # The URL path that was called e.g. "/datasets/upload"
    )
    http_method: Mapped[str | None] = mapped_column(
        String(10),
        nullable=True,
        # GET, POST, DELETE etc.
    )

    # Timestamp — indexed for time-range queries
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    # ---------------------------------------------------------------- #
    #  Relationship                                                      #
    # ---------------------------------------------------------------- #

    user: Mapped["User | None"] = relationship(
        "User",
        back_populates="audit_logs",
        lazy="select",
    )

    # ---------------------------------------------------------------- #
    #  Helpers                                                           #
    # ---------------------------------------------------------------- #

    def __repr__(self) -> str:
        return (
            f"<AuditLog id={self.id} action={self.action} "
            f"user_id={self.user_id} success={self.success}>"
        )

    @classmethod
    def create(
        cls,
        *,
        action: AuditAction,
        resource_type: ResourceType,
        user_id: uuid.UUID | None = None,
        resource_id: str | None = None,
        success: bool = True,
        error_detail: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        endpoint: str | None = None,
        http_method: str | None = None,
    ) -> "AuditLog":
        """
        Factory method for creating an AuditLog entry.

        Usage in any endpoint:
            from app.models.audit import AuditLog, AuditAction, ResourceType

            log = AuditLog.create(
                action=AuditAction.DOWNLOAD,
                resource_type=ResourceType.DATASET,
                user_id=current_user.id,
                resource_id=str(dataset_id),
                ip_address=request.client.host,
            )
            db.add(log)
            db.commit()
        """
        return cls(
            action=action,
            resource_type=resource_type,
            user_id=user_id,
            resource_id=resource_id,
            success=success,
            error_detail=error_detail,
            ip_address=ip_address,
            user_agent=user_agent,
            endpoint=endpoint,
            http_method=http_method,
        )
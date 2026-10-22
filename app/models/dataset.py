import uuid
import os
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    Boolean, DateTime, Enum, ForeignKey,
    Integer, String, Text, func
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


# ------------------------------------------------------------------ #
#  Dataset type enum                                                   #
#                                                                      #
#  Classifies what kind of oceanographic data the dataset contains.   #
#  This is used in metadata search and filtering.                      #
# ------------------------------------------------------------------ #

class DatasetType(str, PyEnum):
    BATHYMETRIC   = "bathymetric"    # seafloor depth mapping
    CTD_PROFILE   = "ctd_profile"    # conductivity, temp, depth casts
    AIS_LOG       = "ais_log"        # vessel tracking data
    SONAR         = "sonar"          # acoustic survey data
    WATER_SAMPLE  = "water_sample"   # chemical/biological samples
    METEOROLOGICAL = "meteorological" # weather/ocean surface data
    OTHER         = "other"


# ------------------------------------------------------------------ #
#  Dataset model                                                       #
# ------------------------------------------------------------------ #

class Dataset(Base):
    __tablename__ = "datasets"

    # Primary key — UUID, not guessable integer
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # Metadata — what this dataset is
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    data_type: Mapped[DatasetType] = mapped_column(
        Enum(DatasetType),
        nullable=False,
        default=DatasetType.OTHER,
        index=True,
    )
    tags: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        # Comma-separated tags e.g. "atlantic, 2024, deepwater"
        # For a production system, this would be a separate tags table
    )

    # Geographic context
    region: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        # e.g. "Celtic Sea", "North Atlantic", "Irish Exclusive EEZ"
    )
    collection_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # File storage
    # SECURITY: file_path stores the server-side path only.
    # It is NEVER exposed in API responses — only the dataset ID
    # is returned so clients cannot guess or enumerate file paths.
    file_path: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )
    original_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        # The sanitised original name for display purposes only
    )
    file_size_bytes: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    mime_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    # Ownership and access control
    uploader_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        # RESTRICT: cannot delete a user who has uploaded datasets
        nullable=False,
        index=True,
    )
    institution_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True,
        # Datasets are scoped to an institution.
        # Researchers can only download datasets from their institution
        # unless is_public=True or they are sys_admin.
    )
    is_public: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        # Public datasets can be downloaded by any authenticated user
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        # Soft delete — set False instead of removing the row
        # so audit logs remain valid
    )

    # Timestamps
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

    # ---------------------------------------------------------------- #
    #  Relationships                                                     #
    # ---------------------------------------------------------------- #

    uploader: Mapped["User"] = relationship(
        "User",
        back_populates="datasets",
        lazy="select",
    )

    # ---------------------------------------------------------------- #
    #  Helpers                                                           #
    # ---------------------------------------------------------------- #

    def __repr__(self) -> str:
        return (
            f"<Dataset id={self.id} title={self.title!r} "
            f"type={self.data_type}>"
        )

    @property
    def file_size_mb(self) -> float | None:
        """File size in megabytes, rounded to 2 decimal places."""
        if self.file_size_bytes is None:
            return None
        return round(self.file_size_bytes / (1024 * 1024), 2)

    @property
    def file_extension(self) -> str:
        """File extension extracted from the original filename."""
        _, ext = os.path.splitext(self.original_filename)
        return ext.lower()
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.models.dataset import DatasetType


# ------------------------------------------------------------------ #
#  Request schemas                                                     #
# ------------------------------------------------------------------ #

class DatasetMetadata(BaseModel):
    """
    Metadata submitted alongside a file upload.
    The file itself is sent as multipart form data.
    """
    title: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="Descriptive title for the dataset.",
        examples=["Celtic Sea Bathymetric Survey 2024"],
    )
    description: Optional[str] = Field(
        None,
        max_length=2000,
        description="Full description of the dataset contents.",
        examples=["Multibeam sonar survey of the Celtic Sea shelf edge."],
    )
    data_type: DatasetType = Field(
        ...,
        description="Category of oceanographic data.",
        examples=["bathymetric"],
    )
    region: Optional[str] = Field(
        None,
        max_length=255,
        description="Geographic region of the data collection.",
        examples=["Celtic Sea"],
    )
    tags: Optional[str] = Field(
        None,
        max_length=500,
        description="Comma-separated tags for search.",
        examples=["atlantic, 2024, deepwater, multibeam"],
    )
    collection_date: Optional[datetime] = Field(
        None,
        description="When the data was collected (ISO 8601).",
    )
    is_public: bool = Field(
        default=False,
        description=(
            "If true, any authenticated user can download. "
            "If false, only users from the same institution."
        ),
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "title": "Celtic Sea Bathymetric Survey 2024",
                "description": "Multibeam sonar survey of the Celtic Sea shelf edge.",
                "data_type": "bathymetric",
                "region": "Celtic Sea",
                "tags": "atlantic, 2024, deepwater",
                "is_public": False,
            }
        }
    }


# ------------------------------------------------------------------ #
#  Response schemas                                                    #
# ------------------------------------------------------------------ #

class DatasetResponse(BaseModel):
    """
    Safe dataset response — never includes file_path.
    file_path is a server-side detail that must never be
    exposed to clients.
    """
    id: uuid.UUID
    title: str
    description: Optional[str]
    data_type: DatasetType
    region: Optional[str]
    tags: Optional[str]
    collection_date: Optional[datetime]
    original_filename: str
    file_size_bytes: Optional[int]
    file_size_mb: Optional[float]
    mime_type: Optional[str]
    institution_id: Optional[str]
    is_public: bool
    is_active: bool
    uploader_id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "title": "Celtic Sea Bathymetric Survey 2024",
                "data_type": "bathymetric",
                "region": "Celtic Sea",
                "original_filename": "celtic_sea_survey_2024.csv",
                "file_size_mb": 2.4,
                "is_public": False,
                "institution_id": "marine-institute-ireland",
            }
        }
    }


class DatasetListResponse(BaseModel):
    """Paginated dataset list."""
    total: int
    page: int
    page_size: int
    datasets: list[DatasetResponse]


class DatasetDeleteResponse(BaseModel):
    message: str
    dataset_id: str

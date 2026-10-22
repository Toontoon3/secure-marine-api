import logging
import os
import shutil
import uuid
from typing import Optional

from fastapi import (
    APIRouter, Depends, File, Form,
    HTTPException, Query, Request,
    UploadFile, status,
)
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.core.rbac import (
    get_current_user,
    require_researcher,
    verify_institution_access,
)
from app.database import get_db
from app.models.audit import AuditAction, AuditLog, ResourceType
from app.models.dataset import Dataset, DatasetType
from app.models.user import User
from app.schemas.dataset import (
    DatasetDeleteResponse,
    DatasetListResponse,
    DatasetResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/datasets",
    tags=["Datasets"],
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
    },
)


# ------------------------------------------------------------------ #
#  Helpers                                                             #
# ------------------------------------------------------------------ #

def _write_audit(
    db: Session,
    action: AuditAction,
    request: Request,
    user_id,
    resource_id: str = None,
    success: bool = True,
    error_detail: str = None,
):
    """Write an audit log entry — never raises, never breaks the caller."""
    try:
        forwarded = request.headers.get("X-Forwarded-For")
        ip = forwarded.split(",")[0].strip() if forwarded else (
            request.client.host if request.client else "unknown"
        )
        log = AuditLog.create(
            action=action,
            resource_type=ResourceType.DATASET,
            user_id=user_id,
            resource_id=resource_id,
            success=success,
            error_detail=error_detail,
            ip_address=ip,
            user_agent=request.headers.get("user-agent", "")[:500],
            endpoint=str(request.url.path),
            http_method=request.method,
        )
        db.add(log)
        db.commit()
    except Exception as e:
        logger.error(f"Audit log write failed: {e}")
        db.rollback()


def _validate_file(file: UploadFile) -> None:
    """
    Validate uploaded file type and size.
    Raises HTTP 400 if the file fails validation.
    """
    # Check MIME type
    if file.content_type not in settings.ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"File type '{file.content_type}' is not allowed. "
                f"Accepted types: {', '.join(settings.ALLOWED_MIME_TYPES)}"
            ),
        )

    # Check file extension
    _, ext = os.path.splitext(file.filename or "")
    if ext.lower() not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"File extension '{ext}' is not allowed. "
                f"Accepted extensions: {', '.join(settings.ALLOWED_EXTENSIONS)}"
            ),
        )


def _ensure_upload_dir() -> str:
    """Create the upload directory if it does not exist."""
    upload_dir = settings.UPLOAD_DIR
    os.makedirs(upload_dir, exist_ok=True)
    return upload_dir


def _safe_filename(original: str) -> str:
    """
    Sanitise the original filename and prepend a UUID.
    Prevents path traversal attacks — e.g. '../../etc/passwd'
    becomes a safe name with no directory separators.
    """
    # Strip directory components
    basename = os.path.basename(original)
    # Replace any remaining unsafe characters
    safe = "".join(
        c if c.isalnum() or c in "._- " else "_"
        for c in basename
    ).strip()
    # Prepend UUID so filenames are always unique on disk
    return f"{uuid.uuid4()}_{safe}"


# ------------------------------------------------------------------ #
#  POST /datasets/upload                                               #
# ------------------------------------------------------------------ #

@router.post(
    "/upload",
    response_model=DatasetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a new dataset",
    description=(
        "Upload an oceanographic dataset file with metadata. "
        "Accepted formats: CSV, JSON, NetCDF (.nc, .cdf). "
        "Maximum file size: 50 MB. "
        "Requires **researcher** role or above."
    ),
)
async def upload_dataset(
    request: Request,
    # Form fields — metadata about the dataset
    title: str = Form(..., min_length=3, max_length=255),
    data_type: DatasetType = Form(...),
    description: Optional[str] = Form(None, max_length=2000),
    region: Optional[str] = Form(None, max_length=255),
    tags: Optional[str] = Form(None, max_length=500),
    is_public: bool = Form(default=False),
    # File field
    file: UploadFile = File(
        ...,
        description="Dataset file — CSV, JSON, or NetCDF only.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_researcher),
):
    """
    Upload a dataset file with metadata.

    Steps:
        1. Validate file type and extension
        2. Check file size does not exceed the limit
        3. Save file to disk with a sanitised UUID name
        4. Create Dataset record in the database
        5. Write audit log
        6. Return dataset metadata (never the file path)
    """

    # ---- Step 1: Validate file ------------------------------------ #
    _validate_file(file)

    # ---- Step 2: Check file size ---------------------------------- #
    # Read the file into memory to check size, then we'll write it
    contents = await file.read()
    file_size = len(contents)

    if file_size > settings.max_upload_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"File size ({file_size / 1024 / 1024:.1f} MB) exceeds "
                f"the maximum allowed size ({settings.MAX_UPLOAD_SIZE_MB} MB)."
            ),
        )

    if file_size == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    # ---- Step 3: Save file to disk -------------------------------- #
    upload_dir = _ensure_upload_dir()
    safe_name = _safe_filename(file.filename or "dataset")
    file_path = os.path.join(upload_dir, safe_name)

    try:
        with open(file_path, "wb") as f:
            f.write(contents)
    except Exception as e:
        logger.error(f"Failed to save uploaded file: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save file. Please try again.",
        )

    # ---- Step 4: Create database record -------------------------- #
    dataset = Dataset(
        title=title,
        description=description,
        data_type=data_type,
        region=region,
        tags=tags,
        is_public=is_public,
        file_path=file_path,       # stored server-side only
        original_filename=file.filename or safe_name,
        file_size_bytes=file_size,
        mime_type=file.content_type,
        uploader_id=current_user.id,
        institution_id=current_user.institution_id,
        is_active=True,
    )

    try:
        db.add(dataset)
        db.commit()
        db.refresh(dataset)
    except Exception as e:
        # Clean up the saved file if DB write fails
        if os.path.exists(file_path):
            os.remove(file_path)
        db.rollback()
        logger.error(f"Failed to create dataset record: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save dataset. Please try again.",
        )

    # ---- Step 5: Audit log --------------------------------------- #
    _write_audit(
        db=db,
        action=AuditAction.UPLOAD,
        request=request,
        user_id=current_user.id,
        resource_id=str(dataset.id),
        success=True,
    )

    logger.info(
        f"Dataset uploaded: '{title}' ({file_size / 1024:.1f} KB) "
        f"by {current_user.email}"
    )

    return dataset


# ------------------------------------------------------------------ #
#  GET /datasets/                                                      #
# ------------------------------------------------------------------ #

@router.get(
    "/",
    response_model=DatasetListResponse,
    status_code=status.HTTP_200_OK,
    summary="List datasets",
    description=(
        "List available datasets. Results are filtered by your role: "
        "researchers see their institution's datasets + public datasets; "
        "sys_admin sees everything."
    ),
)
def list_datasets(
    request: Request,
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Results per page"),
    data_type: Optional[DatasetType] = Query(None, description="Filter by data type"),
    region: Optional[str] = Query(None, description="Filter by region"),
    public_only: bool = Query(False, description="Show only public datasets"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Return a paginated, role-filtered list of datasets.
    """
    query = db.query(Dataset).filter(Dataset.is_active == True)

    # ---- RBAC filter --------------------------------------------- #
    # sys_admin sees all datasets
    # everyone else sees: their institution's datasets + public ones
    if not current_user.is_sys_admin:
        from sqlalchemy import or_
        query = query.filter(
            or_(
                Dataset.is_public == True,
                Dataset.institution_id == current_user.institution_id,
            )
        )

    # ---- Optional filters --------------------------------------- #
    if data_type:
        query = query.filter(Dataset.data_type == data_type)
    if region:
        query = query.filter(Dataset.region.ilike(f"%{region}%"))
    if public_only:
        query = query.filter(Dataset.is_public == True)

    # ---- Pagination --------------------------------------------- #
    total = query.count()
    datasets = (
        query
        .order_by(Dataset.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    _write_audit(
        db=db,
        action=AuditAction.LIST_DATASETS,
        request=request,
        user_id=current_user.id,
        success=True,
    )

    return DatasetListResponse(
        total=total,
        page=page,
        page_size=page_size,
        datasets=datasets,
    )


# ------------------------------------------------------------------ #
#  GET /datasets/{dataset_id}                                         #
# ------------------------------------------------------------------ #

@router.get(
    "/{dataset_id}",
    response_model=DatasetResponse,
    status_code=status.HTTP_200_OK,
    summary="Get dataset metadata",
    description="Return metadata for a single dataset. Does not download the file.",
)
def get_dataset(
    dataset_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return metadata for one dataset."""
    dataset = db.query(Dataset).filter(
        Dataset.id == dataset_id,
        Dataset.is_active == True,
    ).first()

    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset not found.",
        )

    # Check institution access
    if not verify_institution_access(
        current_user,
        dataset.institution_id,
        dataset.is_public,
    ):
        _write_audit(
            db=db, action=AuditAction.VIEW_METADATA,
            request=request, user_id=current_user.id,
            resource_id=str(dataset_id), success=False,
            error_detail="Institution access denied.",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have access to this dataset.",
        )

    _write_audit(
        db=db, action=AuditAction.VIEW_METADATA,
        request=request, user_id=current_user.id,
        resource_id=str(dataset_id), success=True,
    )

    return dataset


# ------------------------------------------------------------------ #
#  GET /datasets/{dataset_id}/download                                #
# ------------------------------------------------------------------ #

@router.get(
    "/{dataset_id}/download",
    status_code=status.HTTP_200_OK,
    summary="Download a dataset file",
    description=(
        "Stream the dataset file to the client. "
        "Access is restricted by institution membership unless "
        "the dataset is marked public."
    ),
)
def download_dataset(
    dataset_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Download a dataset file.

    Security checks:
        1. Dataset must exist and be active
        2. User must have institution access or dataset must be public
        3. File must exist on disk
    """

    # ---- Find dataset -------------------------------------------- #
    dataset = db.query(Dataset).filter(
        Dataset.id == dataset_id,
        Dataset.is_active == True,
    ).first()

    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset not found.",
        )

    # ---- Institution access check -------------------------------- #
    if not verify_institution_access(
        current_user,
        dataset.institution_id,
        dataset.is_public,
    ):
        _write_audit(
            db=db, action=AuditAction.DOWNLOAD,
            request=request, user_id=current_user.id,
            resource_id=str(dataset_id), success=False,
            error_detail="Institution access denied on download.",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to download this dataset.",
        )

    # ---- Confirm file exists on disk ----------------------------- #
    if not os.path.exists(dataset.file_path):
        logger.error(
            f"File missing on disk for dataset {dataset_id}: "
            f"{dataset.file_path}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Dataset file not found on server. Contact an administrator.",
        )

    # ---- Audit log ---------------------------------------------- #
    _write_audit(
        db=db, action=AuditAction.DOWNLOAD,
        request=request, user_id=current_user.id,
        resource_id=str(dataset_id), success=True,
    )

    logger.info(
        f"Dataset downloaded: '{dataset.title}' "
        f"by {current_user.email}"
    )

    # ---- Stream the file ----------------------------------------- #
    # FileResponse streams the file efficiently without loading
    # it entirely into memory. The filename header tells the browser
    # what to name the downloaded file.
    return FileResponse(
        path=dataset.file_path,
        filename=dataset.original_filename,
        media_type=dataset.mime_type or "application/octet-stream",
    )


# ------------------------------------------------------------------ #
#  DELETE /datasets/{dataset_id}                                      #
# ------------------------------------------------------------------ #

@router.delete(
    "/{dataset_id}",
    response_model=DatasetDeleteResponse,
    status_code=status.HTTP_200_OK,
    summary="Delete a dataset",
    description=(
        "Soft-delete a dataset. Only the uploader or an admin can delete. "
        "The record is marked inactive — not permanently removed — "
        "so audit logs remain valid."
    ),
)
def delete_dataset(
    dataset_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    dataset = db.query(Dataset).filter(
        Dataset.id == dataset_id,
        Dataset.is_active == True,
    ).first()

    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset not found.",
        )

    # Only the uploader or an admin can delete
    if (
        dataset.uploader_id != current_user.id
        and not current_user.is_admin
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the dataset uploader or an admin can delete this dataset.",
        )

    # Soft delete — set inactive, do not remove the row
    dataset.is_active = False
    db.commit()

    _write_audit(
        db=db, action=AuditAction.DELETE_DATASET,
        request=request, user_id=current_user.id,
        resource_id=str(dataset_id), success=True,
    )

    return DatasetDeleteResponse(
        message="Dataset successfully deleted.",
        dataset_id=str(dataset_id),
    )

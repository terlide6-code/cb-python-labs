"""Record endpoints."""

import logging
from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Path, Query, Response, status

from labs.lab03 import repository
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/records", tags=["records"])
RecordId = Annotated[int, Path(gt=0)]


def _conflict(error: repository.ConflictError) -> HTTPException:
    return HTTPException(status_code=409, detail="Duplicate code or unknown category")


@router.get("", response_model=list[RecordRead])
def get_records(
    category_id: Annotated[int | None, Query(gt=0)] = None,
    status_filter: Annotated[
        str | None, Query(alias="status", pattern="^(new|in_progress|done)$")
    ] = None,
    min_value: Annotated[float | None, Query(ge=0, le=10)] = None,
    q: Annotated[str | None, Query(min_length=1, max_length=120)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict]:
    """List records, optionally filtered with AND semantics."""
    return repository.list_records(
        category_id, status_filter, min_value, q, limit, offset
    )


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    responses={404: {"description": "Record not found"}},
)
def get_record(record_id: RecordId) -> dict:
    """Return one record."""
    try:
        return repository.get_record(record_id)
    except repository.NotFoundError as error:
        raise HTTPException(status_code=404, detail="Record not found") from error
    except Exception as error:
        logger.exception("Unable to read record")
        raise HTTPException(status_code=500, detail="Internal server error") from error


@router.post(
    "",
    response_model=RecordRead,
    status_code=status.HTTP_201_CREATED,
    responses={
        404: {"description": "Category not found"},
        409: {"description": "Duplicate record code"},
    },
)
def post_record(record: RecordCreate) -> dict:
    """Create one record."""
    try:
        return repository.create_record(record)
    except repository.CategoryNotFoundError as error:
        raise HTTPException(status_code=404, detail="Category not found") from error
    except repository.ConflictError as error:
        raise _conflict(error) from error
    except Exception as error:
        logger.exception("Unable to create record")
        raise HTTPException(status_code=500, detail="Internal server error") from error


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    responses={
        404: {"description": "Record or category not found"},
        409: {"description": "Duplicate record code"},
    },
)
def put_record(record_id: RecordId, record: RecordReplace) -> dict:
    """Replace all mutable fields of one record."""
    try:
        return repository.replace_record(record_id, record)
    except repository.CategoryNotFoundError as error:
        raise HTTPException(status_code=404, detail="Category not found") from error
    except repository.NotFoundError as error:
        raise HTTPException(status_code=404, detail="Record not found") from error
    except repository.ConflictError as error:
        raise _conflict(error) from error
    except Exception as error:
        logger.exception("Unable to update record")
        raise HTTPException(status_code=500, detail="Internal server error") from error


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={404: {"description": "Record not found"}},
)
def remove_record(record_id: RecordId) -> Response:
    """Delete one record."""
    try:
        repository.delete_record(record_id)
    except repository.NotFoundError as error:
        raise HTTPException(status_code=404, detail="Record not found") from error
    except Exception as error:
        logger.exception("Unable to delete record")
        raise HTTPException(status_code=500, detail="Internal server error") from error
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
    responses={
        404: {"description": "Category not found"},
        409: {"description": "Duplicate record code"},
    },
)
def post_records_bulk(
    records: Annotated[list[RecordCreate], Body(min_length=1, max_length=100)],
) -> list[dict]:
    """Insert between one and one hundred records atomically."""
    try:
        return repository.create_records_bulk(records)
    except repository.CategoryNotFoundError as error:
        raise HTTPException(status_code=404, detail="Category not found") from error
    except repository.ConflictError as error:
        raise _conflict(error) from error
    except Exception as error:
        logger.exception("Unable to create records in bulk")
        raise HTTPException(status_code=500, detail="Internal server error") from error

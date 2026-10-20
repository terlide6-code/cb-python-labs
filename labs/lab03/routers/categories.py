"""Category endpoints."""

import logging
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Response, status

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/categories", tags=["categories"])
CategoryId = Annotated[int, Path(gt=0)]


@router.get("", response_model=list[CategoryRead])
def get_categories() -> list[dict]:
    """List categories."""
    return repository.list_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=status.HTTP_201_CREATED,
    responses={409: {"description": "Category name already exists"}},
)
def post_category(category: CategoryCreate) -> dict:
    """Create a category."""
    try:
        return repository.create_category(category.name)
    except repository.ConflictError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Category already exists"
        ) from error
    except Exception as error:
        logger.exception("Unable to create category")
        raise HTTPException(status_code=500, detail="Internal server error") from error


@router.delete(
    "/{category_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        404: {"description": "Category not found"},
        409: {"description": "Category contains records"},
    },
)
def remove_category(category_id: CategoryId) -> Response:
    """Delete a category when it has no records."""
    try:
        repository.delete_category(category_id)
    except repository.NotFoundError as error:
        raise HTTPException(status_code=404, detail="Category not found") from error
    except repository.RestrictedDeleteError as error:
        raise HTTPException(
            status_code=409, detail="Category contains records"
        ) from error
    except Exception as error:
        logger.exception("Unable to delete category")
        raise HTTPException(status_code=500, detail="Internal server error") from error
    return Response(status_code=status.HTTP_204_NO_CONTENT)

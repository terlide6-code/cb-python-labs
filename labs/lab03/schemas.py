"""Pydantic request and response models for the REST API."""

import math
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from labs.lab03.config import ALLOWED_STATUSES

Status = Literal["new", "in_progress", "done"]
Name = Annotated[str, Field(min_length=2, max_length=40)]
Code = Annotated[str, Field(min_length=3, max_length=40)]
Title = Annotated[str, Field(min_length=3, max_length=120)]
Identifier = Annotated[int, Field(gt=0)]
DangerValue = Annotated[float, Field(ge=0, le=10, allow_inf_nan=False)]


class StrictModel(BaseModel):
    """Reject undeclared request fields and implicit type conversions."""

    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)


class CategoryCreate(StrictModel):
    """Payload for a new category."""

    name: Name

    @field_validator("name")
    @classmethod
    def name_is_not_blank(cls, value: str) -> str:
        """Forbid strings consisting only of whitespace."""
        if not value.strip():
            raise ValueError("name must not be blank")
        return value


class CategoryRead(BaseModel):
    """Category returned by the API."""

    id: int
    name: str


class RecordPayload(StrictModel):
    """Shared validation for creating and replacing a record."""

    category_id: Identifier
    code: Code
    title: Title
    value: DangerValue
    status: Status

    @field_validator("code", "title")
    @classmethod
    def string_is_not_blank(cls, value: str) -> str:
        """Forbid whitespace-only codes and titles."""
        if not value.strip():
            raise ValueError("value must not be blank")
        return value

    @field_validator("value")
    @classmethod
    def value_is_finite(cls, value: float) -> float:
        """SQLite must not receive NaN or infinity."""
        if not math.isfinite(value):
            raise ValueError("value must be finite")
        return value


class RecordCreate(RecordPayload):
    """Payload for creating a record."""


class RecordReplace(RecordPayload):
    """Full payload for replacing an existing record."""


class RecordRead(BaseModel):
    """Record with its category name, returned by the API."""

    id: int
    category_id: int
    category_name: str
    code: str
    title: str
    value: float
    status: Status


assert set(ALLOWED_STATUSES) == {"new", "in_progress", "done"}

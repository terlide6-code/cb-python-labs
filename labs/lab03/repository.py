"""Parameterized SQLite queries for laboratory work #3."""

import sqlite3
from collections.abc import Sequence
from typing import Any

from labs.lab03.database import get_connection


class RepositoryError(Exception):
    """Base class for expected repository errors."""


class NotFoundError(RepositoryError):
    """Requested resource does not exist."""


class ConflictError(RepositoryError):
    """A uniqueness or foreign-key constraint was violated."""


class RestrictedDeleteError(ConflictError):
    """A category with related records cannot be deleted."""


class CategoryNotFoundError(NotFoundError):
    """A record payload refers to a category that does not exist."""


RECORD_COLUMNS = """
    records.id, records.category_id, categories.name AS category_name,
    records.code, records.title, records.value, records.status
"""


def _record_from_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def _raise_integrity_error(error: sqlite3.IntegrityError) -> None:
    message = str(error).lower()
    if "foreign key" in message:
        raise CategoryNotFoundError("Referenced category does not exist") from error
    raise ConflictError("Duplicate or invalid data") from error


def list_categories() -> list[dict[str, Any]]:
    """Return all categories in identifier order."""
    with get_connection() as connection:
        return [
            dict(row)
            for row in connection.execute("SELECT id, name FROM categories ORDER BY id")
        ]


def create_category(name: str) -> dict[str, Any]:
    """Insert one category."""
    try:
        with get_connection() as connection:
            cursor = connection.execute(
                "INSERT INTO categories (name) VALUES (?)", (name,)
            )
            row = connection.execute(
                "SELECT id, name FROM categories WHERE id = ?", (cursor.lastrowid,)
            ).fetchone()
            return dict(row)
    except sqlite3.IntegrityError as error:
        _raise_integrity_error(error)


def delete_category(category_id: int) -> None:
    """Delete an empty category."""
    try:
        with get_connection() as connection:
            cursor = connection.execute(
                "DELETE FROM categories WHERE id = ?", (category_id,)
            )
            if cursor.rowcount == 0:
                raise NotFoundError("Category not found")
    except sqlite3.IntegrityError as error:
        raise RestrictedDeleteError("Category contains records") from error


def list_records(
    category_id: int | None,
    status: str | None,
    min_value: float | None,
    query: str | None,
    limit: int,
    offset: int,
) -> list[dict[str, Any]]:
    """Return filtered records; every user value is bound as a parameter."""
    conditions: list[str] = []
    parameters: list[Any] = []
    if category_id is not None:
        conditions.append("records.category_id = ?")
        parameters.append(category_id)
    if status is not None:
        conditions.append("records.status = ?")
        parameters.append(status)
    if min_value is not None:
        conditions.append("records.value >= ?")
        parameters.append(min_value)
    if query is not None:
        conditions.append("instr(records.title, ?) > 0")
        parameters.append(query)

    where_clause = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    statement = (
        f"SELECT {RECORD_COLUMNS} FROM records "
        f"JOIN categories ON categories.id = records.category_id{where_clause} "
        "ORDER BY records.id ASC LIMIT ? OFFSET ?"
    )
    parameters.extend((limit, offset))
    with get_connection() as connection:
        return [dict(row) for row in connection.execute(statement, parameters)]


def get_record(record_id: int) -> dict[str, Any]:
    """Return one record or raise a not-found error."""
    statement = (
        f"SELECT {RECORD_COLUMNS} FROM records "
        "JOIN categories ON categories.id = records.category_id WHERE records.id = ?"
    )
    with get_connection() as connection:
        row = connection.execute(statement, (record_id,)).fetchone()
    record = _record_from_row(row)
    if record is None:
        raise NotFoundError("Record not found")
    return record


def _record_values(record: Any) -> tuple[int, str, str, float, str]:
    return (record.category_id, record.code, record.title, record.value, record.status)


def _category_exists(connection: sqlite3.Connection, category_id: int) -> bool:
    """Return whether a category identifier exists."""
    return (
        connection.execute(
            "SELECT 1 FROM categories WHERE id = ?", (category_id,)
        ).fetchone()
        is not None
    )


def create_record(record: Any) -> dict[str, Any]:
    """Insert one record and return it with its category name."""
    try:
        with get_connection() as connection:
            if not _category_exists(connection, record.category_id):
                raise CategoryNotFoundError("Category not found")
            cursor = connection.execute(
                "INSERT INTO records (category_id, code, title, value, status) VALUES (?, ?, ?, ?, ?)",
                _record_values(record),
            )
            row = connection.execute(
                f"SELECT {RECORD_COLUMNS} FROM records "
                "JOIN categories ON categories.id = records.category_id WHERE records.id = ?",
                (cursor.lastrowid,),
            ).fetchone()
            return dict(row)
    except sqlite3.IntegrityError as error:
        _raise_integrity_error(error)


def replace_record(record_id: int, record: Any) -> dict[str, Any]:
    """Fully update an existing record."""
    try:
        with get_connection() as connection:
            if not _category_exists(connection, record.category_id):
                raise CategoryNotFoundError("Category not found")
            cursor = connection.execute(
                """
                UPDATE records
                SET category_id = ?, code = ?, title = ?, value = ?, status = ?
                WHERE id = ?
                """,
                (*_record_values(record), record_id),
            )
            if cursor.rowcount == 0:
                raise NotFoundError("Record not found")
            row = connection.execute(
                f"SELECT {RECORD_COLUMNS} FROM records "
                "JOIN categories ON categories.id = records.category_id WHERE records.id = ?",
                (record_id,),
            ).fetchone()
            return dict(row)
    except sqlite3.IntegrityError as error:
        _raise_integrity_error(error)


def delete_record(record_id: int) -> None:
    """Delete one record."""
    with get_connection() as connection:
        cursor = connection.execute("DELETE FROM records WHERE id = ?", (record_id,))
        if cursor.rowcount == 0:
            raise NotFoundError("Record not found")


def create_records_bulk(records: Sequence[Any]) -> list[dict[str, Any]]:
    """Insert all supplied records in one atomic transaction."""
    try:
        with get_connection() as connection:
            connection.execute("BEGIN")
            category_ids = {record.category_id for record in records}
            for category_id in category_ids:
                if not _category_exists(connection, category_id):
                    raise CategoryNotFoundError("Category not found")
            cursor = connection.executemany(
                "INSERT INTO records (category_id, code, title, value, status) VALUES (?, ?, ?, ?, ?)",
                [_record_values(record) for record in records],
            )
            del cursor
            codes = [record.code for record in records]
            placeholders = ", ".join("?" for _ in codes)
            rows = connection.execute(
                f"SELECT {RECORD_COLUMNS} FROM records "
                "JOIN categories ON categories.id = records.category_id "
                f"WHERE records.code IN ({placeholders}) ORDER BY records.id ASC",
                codes,
            ).fetchall()
            return [dict(row) for row in rows]
    except sqlite3.IntegrityError as error:
        _raise_integrity_error(error)

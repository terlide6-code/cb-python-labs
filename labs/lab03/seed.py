"""Idempotently load the initial variant data into SQLite."""

import json
import sqlite3
from typing import Any

from labs.lab03.config import LAB_DIRECTORY
from labs.lab03.database import get_connection, initialize_database
from labs.lab03.schemas import CategoryCreate, RecordCreate

SEED_PATH = LAB_DIRECTORY / "data" / "seed.json"


def _validate_seed(payload: Any) -> tuple[list[dict[str, Any]], list[RecordCreate]]:
    """Validate the complete JSON payload before starting a write transaction."""
    if not isinstance(payload, dict):
        raise TypeError("Seed JSON must be an object")
    categories = payload.get("categories")
    records = payload.get("records")
    if not isinstance(categories, list) or not isinstance(records, list):
        raise TypeError("Seed JSON must contain category and record lists")
    if len(categories) != 3 or len(records) != 8:
        raise ValueError("Seed JSON must contain 3 categories and 8 records")

    validated_categories: list[dict[str, Any]] = []
    for category in categories:
        if not isinstance(category, dict) or set(category) != {"id", "name"}:
            raise ValueError("Each category must contain only id and name")
        category_id = category["id"]
        if type(category_id) is not int or category_id <= 0:
            raise ValueError("Category id must be a positive integer")
        validated_categories.append(
            {"id": category_id, "name": CategoryCreate(name=category["name"]).name}
        )
    if [category["id"] for category in validated_categories] != [1, 2, 3]:
        raise ValueError("Category ids must be 1, 2 and 3")
    if len({category["name"] for category in validated_categories}) != 3:
        raise ValueError("Category names must be unique")

    validated_records = [RecordCreate.model_validate(record) for record in records]
    if len({record.code for record in validated_records}) != 8:
        raise ValueError("Record codes must be unique")
    if any(record.category_id not in {1, 2, 3} for record in validated_records):
        raise ValueError("Record category must exist in seed categories")
    return validated_categories, validated_records


def seed_database() -> bool:
    """Insert the initial package once, without changing a non-empty database."""
    payload = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    categories, records = _validate_seed(payload)
    initialize_database()
    with get_connection() as connection:
        has_data = connection.execute(
            "SELECT EXISTS(SELECT 1 FROM categories) OR EXISTS(SELECT 1 FROM records)"
        ).fetchone()[0]
        if has_data:
            return False
        with connection:
            for category in categories:
                connection.execute(
                    "INSERT INTO categories (id, name) VALUES (?, ?)",
                    (category["id"], category["name"]),
                )
            connection.executemany(
                """
                INSERT INTO records (category_id, code, title, value, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        record.category_id,
                        record.code,
                        record.title,
                        record.value,
                        record.status,
                    )
                    for record in records
                ],
            )
    return True


if __name__ == "__main__":
    try:
        was_seeded = seed_database()
    except (OSError, ValueError, json.JSONDecodeError, sqlite3.Error) as error:
        print(f"Unable to load initial data: {error}")
        raise SystemExit(1) from error
    if was_seeded:
        print("Initial data loaded successfully.")
    else:
        print("Database already contains data; seed was not applied.")

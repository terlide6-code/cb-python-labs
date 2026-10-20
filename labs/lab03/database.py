"""SQLite connection and schema initialization helpers."""

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager

from labs.lab03.config import DATA_DIRECTORY, DATABASE_PATH, SCHEMA_PATH


def initialize_database() -> None:
    """Create the database and its tables if they do not exist yet."""
    DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))


@contextmanager
def get_connection() -> Generator[sqlite3.Connection, None, None]:
    """Yield one configured SQLite connection and always close it."""
    DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


if __name__ == "__main__":
    initialize_database()

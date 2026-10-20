"""Configuration and fixed data for laboratory work #3, variant 2."""

from pathlib import Path

LAB_DIRECTORY = Path(__file__).resolve().parent
DATA_DIRECTORY = LAB_DIRECTORY / "data"
DATABASE_PATH = DATA_DIRECTORY / "lab3.sqlite3"
SCHEMA_PATH = LAB_DIRECTORY / "schema.sql"

ALLOWED_STATUSES = ("new", "in_progress", "done")
DANGER_THRESHOLD = 6.0
VALUE_UNIT = "score"

"""FastAPI application for laboratory work #3."""

import logging

from fastapi import FastAPI

from labs.lab03.database import initialize_database
from labs.lab03.routers.categories import router as categories_router
from labs.lab03.routers.records import router as records_router
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="Реєстр вразливостей мережевих сервісів",
    description=(
        "Облік результатів навчальної перевірки безпеки мережевих сервісів. "
        "Одиниця value: score (оцінка небезпеки від 0 до 10)."
    ),
    version="1.0.0",
)
app.include_router(categories_router)
app.include_router(records_router)


@app.on_event("startup")
def startup() -> None:
    """Ensure that the database exists before accepting requests."""
    initialize_database()


@app.get("/ping")
def ping() -> dict[str, str]:
    """Simple service health check."""
    return {"status": "ok"}


@app.get("/student")
def student() -> dict[str, str | int]:
    """Return student data from the shared project module."""
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }

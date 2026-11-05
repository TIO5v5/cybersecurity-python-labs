"""Головний модуль FastAPI-застосунку Лабораторної роботи №3 (Варіант 11)."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from labs.lab03.config import (
    DOMAIN_DESCRIPTION,
    DOMAIN_TITLE,
    MAX_VALUE,
    MIN_VALUE,
    THRESHOLD,
    UNIT,
)
from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from labs.lab03.schemas import PingResponse, StudentResponse
from shared import student


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Ініціалізувати таблиці SQLite під час запуску сервера."""
    initialize_database()
    yield


app = FastAPI(
    title=f"ЛР №3 — {DOMAIN_TITLE}",
    description=(
        f"{DOMAIN_DESCRIPTION}\n\n"
        f"- **Одиниця вимірювання (`unit`)**: `{UNIT}`\n"
        f"- **Діапазон значень (`value`)**: від `{MIN_VALUE}` до `{MAX_VALUE}`\n"
        f"- **Поріг реагування (`threshold`)**: `{THRESHOLD}`"
    ),
    version="1.0.0",
    lifespan=lifespan,
)


@app.get(
    "/ping",
    response_model=PingResponse,
    tags=["system"],
    summary="Перевірка доступності API",
)
def ping() -> dict[str, str]:
    """Перевірити працездатність вебсервісу."""
    return {"status": "ok"}


@app.get(
    "/student",
    response_model=StudentResponse,
    tags=["system"],
    summary="Дані студента з shared/student.py",
)
def get_student() -> dict[str, str | int]:
    """Повернути ПІБ, групу та номер варіанта студента."""
    if hasattr(student, "get_student_info"):
        info = student.get_student_info()
        if isinstance(info, dict):
            return {
                "student_name": str(
                    info.get("student_name")
                    or info.get("name")
                    or info.get("full_name")
                ),
                "group_name": str(info.get("group_name") or info.get("group")),
                "variant_number": int(
                    info.get("variant_number") or info.get("variant")
                ),
            }

    return {
        "student_name": getattr(
            student,
            "STUDENT_NAME",
            getattr(student, "FULL_NAME", "Ткаченко Ілля Олександрович"),
        ),
        "group_name": getattr(
            student, "GROUP_NAME", getattr(student, "GROUP", "КБ-201")
        ),
        "variant_number": int(
            getattr(student, "VARIANT_NUMBER", getattr(student, "VARIANT", 11))
        ),
    }


app.include_router(categories.router)
app.include_router(records.router)

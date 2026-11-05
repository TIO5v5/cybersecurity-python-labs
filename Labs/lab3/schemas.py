"""Pydantic-моделі запитів і відповідей для Варіанта 11."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from labs.lab03.config import MAX_VALUE, MIN_VALUE

StatusType = Literal["new", "in_progress", "done"]


class CategoryCreate(BaseModel):
    """Модель створення категорії."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(
        min_length=2,
        max_length=40,
        description="Унікальна назва каналу зв'язку (2..40 символів)",
    )


class CategoryRead(CategoryCreate):
    """Модель читання категорії."""

    id: int = Field(gt=0, description="Ідентифікатор категорії")


class RecordCreate(BaseModel):
    """Модель створення запису про завантаження каналу."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    code: str = Field(
        min_length=3,
        max_length=40,
        description="Унікальний код вимірювання (наприклад, V11-01)",
    )
    title: str = Field(
        min_length=3,
        max_length=120,
        description="Назва вимірювання каналу (3..120 символів)",
    )
    category_id: int = Field(
        gt=0,
        description="ID категорії каналу зв'язку",
    )
    value: float = Field(
        ge=MIN_VALUE,
        le=MAX_VALUE,
        allow_inf_nan=False,
        description="Використання пропускної здатності у відсотках (0..100%)",
    )
    status: StatusType = Field(
        description="Стан перевірки вимірювання (new, in_progress, done)",
    )


class RecordReplace(RecordCreate):
    """Модель повної заміни змінюваних полів запису (PUT)."""


class RecordRead(RecordCreate):
    """Модель читання запису разом із назвою категорії."""

    id: int = Field(gt=0, description="Ідентифікатор запису")
    category_name: str = Field(description="Назва категорії каналу")


class SeedData(BaseModel):
    """Модель перевірки структури початкового набору даних seed.json."""

    model_config = ConfigDict(extra="forbid")

    categories: list[CategoryRead] = Field(min_length=3, max_length=3)
    records: list[RecordCreate] = Field(min_length=8, max_length=8)


class StudentResponse(BaseModel):
    """Модель відповіді маршруту /student."""

    student_name: str
    group_name: str
    variant_number: int


class PingResponse(BaseModel):
    """Модель відповіді маршруту /ping."""

    status: str

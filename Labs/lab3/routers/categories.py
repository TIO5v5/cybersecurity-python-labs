"""Маршрути для роботи з категоріями каналів зв'язку."""

from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, status

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["categories"])


@router.get(
    "",
    response_model=list[CategoryRead],
    summary="Список категорій за зростанням id",
)
def get_categories() -> list[dict]:
    """Отримати всі категорії каналів зв'язку."""
    return repository.list_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створення нової категорії",
    responses={
        409: {"description": "Категорія з такою назвою вже існує"},
    },
)
def create_category(payload: CategoryCreate) -> dict:
    """Створити нову категорію каналу зв'язку."""
    try:
        return repository.create_category(payload)
    except repository.ConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@router.delete(
    "/{category_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалення порожньої категорії",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Категорія містить пов'язані записи"},
    },
)
def delete_category(
    category_id: Annotated[
        int,
        Path(gt=0, description="Додатний ідентифікатор категорії"),
    ],
) -> None:
    """Видалити порожню категорію за її ідентифікатором."""
    try:
        repository.delete_category(category_id)
    except repository.NotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except repository.ConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

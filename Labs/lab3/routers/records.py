"""Маршрути для роботи із записами вимірювань завантаження каналів зв'язку."""

from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Path, Query, status

from labs.lab03 import repository
from labs.lab03.config import MAX_VALUE, MIN_VALUE
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace, StatusType

router = APIRouter(prefix="/records", tags=["records"])


@router.get(
    "",
    response_model=list[RecordRead],
    summary="Список записів із фільтрами та пагінацією",
)
def get_records(
    category_id: Annotated[
        int | None,
        Query(gt=0, description="Фільтр за ідентифікатором категорії"),
    ] = None,
    record_status: Annotated[
        StatusType | None,
        Query(alias="status", description="Фільтр за статусом опрацювання"),
    ] = None,
    min_value: Annotated[
        float | None,
        Query(
            ge=MIN_VALUE,
            le=MAX_VALUE,
            allow_inf_nan=False,
            description="Мінімальне значення завантаження каналу (0..100%)",
        ),
    ] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=120,
            description="Буквальний підрядок у полі title (з урахуванням регістру)",
        ),
    ] = None,
    limit: Annotated[
        int,
        Query(ge=1, le=100, description="Максимальна кількість записів"),
    ] = 20,
    offset: Annotated[
        int,
        Query(ge=0, description="Кількість пропущених записів"),
    ] = 0,
) -> list[dict]:
    """Отримати список записів із комбінованими фільтрами."""
    return repository.list_records(
        category_id=category_id,
        status=record_status,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
    summary="Пакетне створення записів в одній транзакції",
    responses={
        404: {"description": "Одне з посилань вказує на неіснуючу категорію"},
        409: {"description": "Дублікат code у базі або всередині пакета"},
    },
)
def create_records_bulk(
    payload: Annotated[
        list[RecordCreate],
        Body(
            min_length=1,
            max_length=100,
            description="Масив від 1 до 100 записів для атомарного збереження",
        ),
    ],
) -> list[dict]:
    """Атомарно зберегти пакет записів або скасувати весь пакет при помилці."""
    try:
        return repository.create_records_bulk(payload)
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


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримати один запис за id",
    responses={
        404: {"description": "Запис не знайдено"},
    },
)
def get_record(
    record_id: Annotated[
        int,
        Path(gt=0, description="Додатний ідентифікатор запису"),
    ],
) -> dict:
    """Отримати деталі запису за його ідентифікатором."""
    try:
        return repository.get_record_by_id(record_id)
    except repository.NotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.post(
    "",
    response_model=RecordRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створення нового запису",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Запис із таким code вже існує"},
    },
)
def create_record(payload: RecordCreate) -> dict:
    """Створити новий запис вимірювання каналу."""
    try:
        return repository.create_record(payload)
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


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повна заміна змінюваних полів запису",
    responses={
        404: {"description": "Запис або категорію не знайдено"},
        409: {"description": "Запис із таким code вже існує"},
    },
)
def replace_record(
    record_id: Annotated[
        int,
        Path(gt=0, description="Додатний ідентифікатор запису"),
    ],
    payload: RecordReplace,
) -> dict:
    """Повністю оновити змінювані поля наявного запису."""
    try:
        return repository.replace_record(record_id, payload)
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


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалення запису",
    responses={
        404: {"description": "Запис не знайдено"},
    },
)
def delete_record(
    record_id: Annotated[
        int,
        Path(gt=0, description="Додатний ідентифікатор запису"),
    ],
) -> None:
    """Видалити запис за його ідентифікатором."""
    try:
        repository.delete_record(record_id)
    except repository.NotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

"""Шар доступу до даних: параметризовані SQL-запити та керування транзакціями."""

import logging
import sqlite3
from contextlib import closing
from typing import Any

from Labs.lab3.database import get_connection
from Labs.lab3.schemas import CategoryCreate, RecordCreate, RecordReplace

logger = logging.getLogger(__name__)


class RepositoryError(Exception):
    """Базовий виняток шару роботи з базою даних."""


class NotFoundError(RepositoryError):
    """Запис або потрібна категорія не існують (відповідає 404)."""


class ConflictError(RepositoryError):
    """Порушення унікальності або зв'язків при видаленні (відповідає 409)."""


SELECT_RECORD_WITH_CATEGORY = """
SELECT
    r.id,
    r.code,
    r.title,
    r.category_id,
    c.name AS category_name,
    r.value,
    r.status
FROM records r
JOIN categories c ON r.category_id = c.id
"""


def list_categories() -> list[dict[str, Any]]:
    """Отримати список усіх категорій за зростанням id."""
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id ASC"
        ).fetchall()
        return [dict(row) for row in rows]


def create_category(data: CategoryCreate) -> dict[str, Any]:
    """Створити нову категорію."""
    with closing(get_connection()) as connection:
        try:
            with connection:
                cursor = connection.execute(
                    "INSERT INTO categories (name) VALUES (?)",
                    (data.name,),
                )
                category_id = cursor.lastrowid
            row = connection.execute(
                "SELECT id, name FROM categories WHERE id = ?",
                (category_id,),
            ).fetchone()
            return dict(row)
        except sqlite3.IntegrityError as exc:
            logger.warning("Конфлікт при створенні категорії: %s", exc)
            raise ConflictError(f"Категорія з назвою '{data.name}' вже існує.") from exc


def delete_category(category_id: int) -> None:
    """Видалити порожню категорію за id."""
    with closing(get_connection()) as connection:
        exists = connection.execute(
            "SELECT 1 FROM categories WHERE id = ?",
            (category_id,),
        ).fetchone()
        if not exists:
            raise NotFoundError(f"Категорію з id={category_id} не знайдено.")

        try:
            with connection:
                connection.execute(
                    "DELETE FROM categories WHERE id = ?",
                    (category_id,),
                )
        except sqlite3.IntegrityError as exc:
            logger.warning(
                "Спроба видалити непорожню категорію id=%d: %s", category_id, exc
            )
            raise ConflictError(
                f"Неможливо видалити категорію id={category_id}, бо вона містить записи."
            ) from exc


def get_record_by_id(record_id: int) -> dict[str, Any]:
    """Отримати один запис за id разом із назвою категорії."""
    with closing(get_connection()) as connection:
        row = connection.execute(
            f"{SELECT_RECORD_WITH_CATEGORY} WHERE r.id = ?",
            (record_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"Запис з id={record_id} не знайдено.")
        return dict(row)


def list_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Отримати список записів із фільтрами та поділом на сторінки."""
    clauses: list[str] = []
    params: list[Any] = []

    if category_id is not None:
        clauses.append("r.category_id = ?")
        params.append(category_id)
    if status is not None:
        clauses.append("r.status = ?")
        params.append(status)
    if min_value is not None:
        clauses.append("r.value >= ?")
        params.append(min_value)
    if q is not None:
        clauses.append("instr(r.title, ?) > 0")
        params.append(q)

    query = SELECT_RECORD_WITH_CATEGORY
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with closing(get_connection()) as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
        return [dict(row) for row in rows]


def create_record(data: RecordCreate) -> dict[str, Any]:
    """Створити новий запис у базі даних."""
    with closing(get_connection()) as connection:
        category = connection.execute(
            "SELECT 1 FROM categories WHERE id = ?",
            (data.category_id,),
        ).fetchone()
        if not category:
            raise NotFoundError(f"Категорію з id={data.category_id} не знайдено.")

        try:
            with connection:
                cursor = connection.execute(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        data.code,
                        data.title,
                        data.category_id,
                        data.value,
                        data.status,
                    ),
                )
                record_id = cursor.lastrowid

            row = connection.execute(
                f"{SELECT_RECORD_WITH_CATEGORY} WHERE r.id = ?",
                (record_id,),
            ).fetchone()
            return dict(row)
        except sqlite3.IntegrityError as exc:
            logger.warning("Конфлікт при створенні запису: %s", exc)
            raise ConflictError(f"Запис із кодом '{data.code}' вже існує.") from exc


def replace_record(record_id: int, data: RecordReplace) -> dict[str, Any]:
    """Повністю оновити змінювані поля запису за id."""
    with closing(get_connection()) as connection:
        existing = connection.execute(
            "SELECT 1 FROM records WHERE id = ?",
            (record_id,),
        ).fetchone()
        if not existing:
            raise NotFoundError(f"Запис з id={record_id} не знайдено.")

        category = connection.execute(
            "SELECT 1 FROM categories WHERE id = ?",
            (data.category_id,),
        ).fetchone()
        if not category:
            raise NotFoundError(f"Категорію з id={data.category_id} не знайдено.")

        try:
            with connection:
                connection.execute(
                    """
                    UPDATE records
                    SET code = ?, title = ?, category_id = ?, value = ?, status = ?
                    WHERE id = ?
                    """,
                    (
                        data.code,
                        data.title,
                        data.category_id,
                        data.value,
                        data.status,
                        record_id,
                    ),
                )

            row = connection.execute(
                f"{SELECT_RECORD_WITH_CATEGORY} WHERE r.id = ?",
                (record_id,),
            ).fetchone()
            return dict(row)
        except sqlite3.IntegrityError as exc:
            logger.warning("Конфлікт при оновленні запису id=%d: %s", record_id, exc)
            raise ConflictError(f"Запис із кодом '{data.code}' вже існує.") from exc


def delete_record(record_id: int) -> None:
    """Видалити запис за id."""
    with closing(get_connection()) as connection:
        existing = connection.execute(
            "SELECT 1 FROM records WHERE id = ?",
            (record_id,),
        ).fetchone()
        if not existing:
            raise NotFoundError(f"Запис з id={record_id} не знайдено.")

        with connection:
            connection.execute(
                "DELETE FROM records WHERE id = ?",
                (record_id,),
            )


def create_records_bulk(items: list[RecordCreate]) -> list[dict[str, Any]]:
    """Пакетно додати записи в межах однієї транзакції."""
    with closing(get_connection()) as connection:
        try:
            with connection:
                created_ids: list[int] = []
                for item in items:
                    category = connection.execute(
                        "SELECT 1 FROM categories WHERE id = ?",
                        (item.category_id,),
                    ).fetchone()
                    if not category:
                        raise NotFoundError(
                            f"Категорію з id={item.category_id} не знайдено."
                        )

                    cursor = connection.execute(
                        """
                        INSERT INTO records (code, title, category_id, value, status)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            item.code,
                            item.title,
                            item.category_id,
                            item.value,
                            item.status,
                        ),
                    )
                    if cursor.lastrowid is not None:
                        created_ids.append(cursor.lastrowid)

            placeholders = ", ".join("?" for _ in created_ids)
            rows = connection.execute(
                f"{SELECT_RECORD_WITH_CATEGORY} WHERE r.id IN ({placeholders}) ORDER BY r.id ASC",
                tuple(created_ids),
            ).fetchall()
            return [dict(row) for row in rows]
        except sqlite3.IntegrityError as exc:
            logger.warning("Конфлікт під час пакетного додавання записів: %s", exc)
            raise ConflictError(
                "Пакет містить дублікат коду code у базі або всередині пакета."
            ) from exc

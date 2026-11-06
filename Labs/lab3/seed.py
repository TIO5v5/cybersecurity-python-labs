"""Модуль початкового заповнення бази даних із файлу seed.json."""

import json
import logging
import sqlite3
from contextlib import closing
from pathlib import Path

from pydantic import ValidationError

from Labs.lab3.database import BASE_DIR, get_connection, initialize_database
from Labs.lab3.schemas import SeedData

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

SEED_PATH = BASE_DIR / "data" / "seed.json"


def seed_database(seed_path: Path = SEED_PATH) -> bool:
    """Заповнити порожню базу даних початковими навчальними даними."""
    initialize_database()

    if not seed_path.exists():
        logger.error("Файл початкових даних не знайдено: %s", seed_path.name)
        return False

    try:
        raw_data = json.loads(seed_path.read_text(encoding="utf-8"))
        seed_data = SeedData.model_validate(raw_data)
    except (json.JSONDecodeError, ValidationError) as exc:
        logger.error("Початкові дані у seed.json некоректні: %s", exc)
        return False

    with closing(get_connection()) as connection:
        cat_count = connection.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
        rec_count = connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]

        if cat_count > 0 or rec_count > 0:
            logger.info(
                "База даних вже містить дані (категорій: %d, записів: %d). "
                "Повторне заповнення пропущено без змін.",
                cat_count,
                rec_count,
            )
            return False

        try:
            with connection:
                connection.executemany(
                    "INSERT INTO categories (id, name) VALUES (?, ?)",
                    [(cat.id, cat.name) for cat in seed_data.categories],
                )
                connection.executemany(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            rec.code,
                            rec.title,
                            rec.category_id,
                            rec.value,
                            rec.status,
                        )
                        for rec in seed_data.records
                    ],
                )
            logger.info(
                "Базу успішно заповнено: додано %d категорії та %d записів.",
                len(seed_data.categories),
                len(seed_data.records),
            )
            return True
        except sqlite3.Error as exc:
            logger.error(
                "Помилка бази даних під час заповнення (транзакцію скасовано): %s",
                exc,
            )
            return False


if __name__ == "__main__":
    seed_database()

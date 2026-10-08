import csv
import hashlib
import json
import os
import sys
from datetime import datetime
from functools import wraps

# Підключення спільного модуля
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import VARIANT_NUMBER

# Налаштування для Варіанту 11
MINIMUM_PASSWORD_LENGTH = 12
# Сіль: варіант 11, доповнений зліва нулями до 5 символів -> "00011"
SALT = f"{VARIANT_NUMBER:05}"

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USER_CSV_DB_PATH = os.path.join(DATA_DIR, "users.csv")
JSON_LOG_PATH = os.path.join(DATA_DIR, "log.json")

# База користувачів у пам'яті
users_db = {}


class ValidationError(Exception):
    """Власний виняток для помилок валідації пароля."""


def log_event(func):
    """Декоратор для логування спроб входу у файл log.json."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)

        # Витягуємо ім'я користувача (перший аргумент або з kwargs)
        username = kwargs.get("username") or (args[0] if args else "Unknown")

        log_entry = {
            "event": "login",
            "user": username,
            "result": "success" if result else "failure",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "args": list(args),
            "kwargs": kwargs,
        }

        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            logs = []
            if os.path.exists(JSON_LOG_PATH):
                with open(JSON_LOG_PATH, "r", encoding="utf-8") as file:
                    try:
                        logs = json.load(file)
                    except json.JSONDecodeError:
                        pass

            logs.append(log_entry)

            with open(JSON_LOG_PATH, "w", encoding="utf-8") as file:
                json.dump(logs, file, indent=4)

        except (FileNotFoundError, PermissionError, OSError) as e:
            print(f"Помилка запису логів: {e}")

        return result

    return wrapper


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує хеш пароля алгоритмом blake2b (Варіант 11)."""
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми")

    if len(password) < MINIMUM_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль закороткий. Мінімум {MINIMUM_PASSWORD_LENGTH} символів."
        )

    # Використовуємо blake2b для 11 варіанту
    h = hashlib.blake2b()
    h.update((password + salt).encode("utf-8"))
    return h.hexdigest()


def create_user(username: str, password: str) -> tuple:
    """Повертає кортеж (username, hash_value)."""
    hash_value = generate_hash(password, SALT)
    return (username, hash_value)


def create_users(users_list: tuple):
    """Створює базу даних у CSV файлі."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(USER_CSV_DB_PATH, mode="w", encoding="utf-8", newline="") as file:
            writer = csv.writer(file)
            for u, p in users_list:
                try:
                    user_data = create_user(u, p)
                    writer.writerow(user_data)
                except (ValueError, ValidationError) as e:
                    print(f"Помилка створення користувача {u}: {e}")
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"Помилка роботи з файлом бази даних: {e}")


@log_event
def login(username: str, password: str) -> bool:
    """Автентифікація користувача."""
    if not username or not password:
        raise ValueError("Логін або пароль порожні")

    if username not in users_db:
        return False

    try:
        expected_hash = generate_hash(password, SALT)
        return users_db[username] == expected_hash
    except (ValueError, ValidationError):
        return False


def main():
    print(f"--- Завдання 3 (Варіант {VARIANT_NUMBER}) ---")

    # 10 користувачів (деякі паролі спеціально коротші 12 символів для перевірки винятку ValidationError)
    users_to_register = (
        ("admin", "SuperSecurePassword123"),
        ("ilya", "MyStrongPass2026!"),
        ("guest", "12345"),  # Закороткий
        ("user1", "VeryLongPassword_11"),
        ("user2", "AnotherSecurePass!"),
        ("user3", "QWERTYUIOPASDFGH"),
        ("user4", "pass"),  # Закороткий
        ("manager", "ManagerPassword_2026"),
        ("auditor", "AuditorPass123456"),
        ("test", "TestingPass12345"),
    )

    print("\n[+] Створення бази користувачів...")
    create_users(users_to_register)

    print("\n[+] Читання CSV бази...")
    try:
        with open(USER_CSV_DB_PATH, mode="r", encoding="utf-8", newline="") as file:
            reader = csv.reader(file)
            print(f"{'Логін':<15} | {'Хеш (blake2b)'}")
            print("-" * 70)
            for row in reader:
                if len(row) == 2:
                    users_db[row[0]] = row[1]
                    print(f"{row[0]:<15} | {row[1][:45]}...")
    except FileNotFoundError:
        print("База даних не знайдена!")
    except (PermissionError, OSError) as e:
        print(f"Помилка доступу до файлу: {e}")

    print("\n[+] Симуляція входу (записується в log.json)...")
    try:
        if login("admin", "SuperSecurePassword123"):
            print("admin: Вхід дозволено!")

        if not login("ilya", "WrongPassword!"):
            print("ilya: Неправильний пароль!")

        # Симуляція ValueError
        login("", "password")
    except ValueError as e:
        print(f"Перехоплено ValueError: {e}")


if __name__ == "__main__":
    main()


# Помилки створення guest та user4: У списку користувачів я спеціально задав їм паролі "12345" та "pass".
# Усі інші 8 користувачів успішно пройшли перевірку, їхні паролі захешовані правильним алгоритмом (blake2b) і виведені на екран.
# "admin: Вхід дозволено!" — демонстрація того, що правильний пароль успішно проходить перевірку через хеш-функцію.
# "ilya: Неправильний пароль!" — демонстрація того, що система працює коректно і відхиляє спроби входу з хибним паролем.
# Перехоплено ValueError: Демонстрація перехоплення винятку ValueError, коли хтось намагається передати порожній рядок замість логіна чи пароля.

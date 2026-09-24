import os
import random
import sys

# Підключення спільного модуля з моїми даними
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані Варіант 11
passwords = [
    "APT@Detect10n",
    "simple",
    "Red@Team2023",
    "participant",
    "Blue@T3am",
    "common123",
    "Purple@T34m",
    "regular123",
    "Gr33n@Team",
    "normal123",
]

criteria = {
    "min_length": 7,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {
    "simple",
    "participant",
    "common123",
    "regular123",
    "normal123",
    "test",
}


def evaluate_password(pwd, pwd_list):
    """Оцінює надійність пароля за 5-ма критеріями."""
    # Заборонений: є у списку (без урахування регістру) або закороткий
    if pwd.lower() in forbidden_passwords or len(pwd) < criteria["min_length"]:
        return "Заборонений"

    # Перевірка наявності різних типів символів
    has_digit = any(c.isdigit() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_special = any(not c.isalnum() for c in pwd)

    met_criteria_count = sum([has_digit, has_upper, has_lower, has_special])
    all_required = has_digit and has_upper and has_special

    # Дуже сильний: всі критерії, довжина >= min+4, унікальний у списку
    if (
        all_required
        and len(pwd) >= criteria["min_length"] + 4
        and pwd_list.count(pwd) == 1
    ):
        return "Дуже сильний"

    # Сильний: всі критерії, але коротший за min+4 або має дублікат
    if all_required:
        return "Сильний"

    # Середній: мін. довжина та деякі (але не всі) критерії
    if met_criteria_count >= 2:
        return "Середній"

    # Слабкий: не заборонений, має хоча б один критерій
    return "Слабкий"


def main():
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 45)

    # Імітація повторного використання паролів (додаємо 3 дублікати)
    for _ in range(3):
        random_idx = random.randint(0, len(passwords) - 1)
        passwords.append(passwords[random_idx])

    # Виведення результатів аналізу у табличному форматі
    print(f"{'Пароль':<20} | {'Надійність':<15}")
    print("-" * 45)
    for p in passwords:
        status = evaluate_password(p, passwords)
        print(f"{p:<20} | {status:<15}")


if __name__ == "__main__":
    main()

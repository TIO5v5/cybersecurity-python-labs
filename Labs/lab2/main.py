import sys

from .task1 import Admin, AuditLog, User, UserAccount


def run_demo():
    print("=== Демонстрація Завдання 1 ===")

    # 1. Створення звичайного користувача
    try:
        user1 = User("illia_kb201", "illia.tkachenko@lpnu.ua")
        user1.set_password("SecurePass123!")
        print(f"Створено користувача: {user1}")
    except ValueError as e:
        print(f"Помилка створення: {e}")

    # 2. Демонстрація валідації email (викличе помилку)
    try:
        print("\nСпроба встановити некоректний email...")
        user1.email = "1bad-email@com"
    except ValueError as e:
        print(f"Спіймано виняток: {e}")

    # 3. Створення адміністратора
    admin1 = Admin("sysadmin", "admin@cyber.local")
    admin1.set_password("AdminPass!#")
    admin1.grant_permission("sudo")
    print(f"\nСтворено адміна: {admin1}")
    print(f"Чи має admin1 права sudo? {admin1.has_permission('sudo')}")

    # 4. Система логіну та композиція
    audit = AuditLog()
    account = UserAccount(user1, audit)

    print("\nСпроба входу з неправильним паролем:")
    account.login("illia_kb201", "WrongPass", "192.168.1.100")

    print("Спроба успішного входу:")
    account.login("illia_kb201", "SecurePass123!", "192.168.1.100")

    print(f"Чи автентифікований користувач? {account.is_authenticated()}")

    # Використання __getitem__
    print(f"\nДоступ через __getitem__: {account['user'].username}")

    # 5. Вихід із системи
    account.logout()

    # 6. Вивід AuditLog
    print("\n=== Журнал аудиту ===")
    audit.show_all()


if __name__ == "__main__":
    # Проста перевірка аргументів для виклику команди demo
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        run_demo()
    else:
        print("Вкажіть команду. Наприклад: python -m labs.lab02.main demo")

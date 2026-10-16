import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# Константа кількості ітерацій для алгоритму PBKDF2.
# Ускладнює перебір паролів (Brute-force), штучно сповільнюючи обчислення хешу.
HASH_ITERATIONS = 100_000


class User:
    """Базовий клас користувача системи (демонстрація Інкапсуляції)."""

    def __init__(
        self, username: str, email: str, role: str = "user", active: bool = True
    ):
        self.username = username
        self.role = role
        self.active = active

        # Protected атрибут (одне підкреслення) для внутрішнього зберігання email
        self._email = None
        # Присвоєння значення через публічну властивість автоматично викликає @email.setter для валідації
        self.email = email

        # Private атрибути (два підкреслення) — вмикають механізм Name Mangling (_User__password_hash).
        # Захищають хеш і сіль від випадкового прямого доступу ззовні та у класах-спадкоємцях.
        self.__password_hash = None
        self.__password_salt = None

    @property
    def email(self) -> str:
        """Геттер (getter): дозволяє читати атрибут user.email як звичайне поле."""
        return self._email

    @email.setter
    def email(self, value: str):
        """Сеттер (setter): автоматично перевіряє формат пошти при кожному записі."""
        # Регулярний вираз:
        # ^[a-zA-Z] — починається з латинської літери
        # [a-zA-Z0-9.]{2,63} — ще від 2 до 63 символів (разом 3–64 символи до @)
        # @[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ — символ @ та домен із принаймні однією крапкою
        pattern = r"^[a-zA-Z][a-zA-Z0-9.]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError("Некоректний формат email адреси.")
        self._email = value

    def set_password(self, password: str) -> None:
        """Безпечне збереження пароля: генерує сіль та обчислює криптостійкий хеш."""
        # Генеруємо випадкову 16-байтну сіль (захист від Rainbow Tables — однакових хешів для однакових паролів)
        self.__password_salt = os.urandom(16)
        # PBKDF2-HMAC-SHA256 замість звичайного sha256, бо звичайний sha256 занадто швидкий для перебору на GPU
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            HASH_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        """Перевіряє введений пароль шляхом повторного хешування з тією самою сіллю."""
        # Якщо пароль ще не був встановлений — відхиляємо вхід
        if not self.__password_hash or not self.__password_salt:
            return False

        # Обчислюємо тестовий хеш для введеного пароля з збереженою сіллю користувача
        test_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            HASH_ITERATIONS,
        )
        # hmac.compare_digest порівнює байти за фіксований час (захист від Timing-атак,
        # щоб зловмисник не вгадав пароль посимвольно за часом затримки відповіді)
        return hmac.compare_digest(self.__password_hash, test_hash)

    def deactivate(self) -> None:
        """Блокує (деактивує) обліковий запис користувача."""
        self.active = False

    def __str__(self) -> str:
        """Спеціальний метод для людиночитабельного виводу об'єкта у консоль (print)."""
        return f"User({self.username}, Role: {self.role}, Active: {self.active})"


# Наслідування від User (принцип "Is-A" — Адміністратор Є Користувачем)
class Admin(User):
    """Клас адміністратора, що розширює User системою дозволів (Наслідування та Поліморфізм)."""

    def __init__(
        self,
        username: str,
        email: str,
        active: bool = True,
        permissions: list | None = None,
    ):
        # Викликаємо конструктор базового класу User і жорстко встановлюємо роль "admin"
        super().__init__(username, email, role="admin", active=active)
        # Використовуємо None як дефолтний аргумент (щоб не передавати змінюваний список []),
        # а права зберігаємо у множині set() для унікальності та миттєвого пошуку за O(1)
        self.permissions = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        """Надає нове право адміністратору."""
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        """Забирає право (discard не викликає помилку, якщо такого права не було)."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Перевіряє наявність конкретного права."""
        return permission in self.permissions

    def __str__(self) -> str:
        """Поліморфізм: перевизначаємо метод базового класу для виводу списку прав."""
        return f"Admin({self.username}, Active: {self.active}, Permissions: {list(self.permissions)})"


class Session:
    """Клас для контролю активного сеансу користувача та відстеження таймауту."""

    def __init__(self, ip: str):
        self.ip = ip
        # Використовуємо UTC із часовим поясом (timezone-aware), щоб уникнути збоїв через часові пояси
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self) -> None:
        """Оновлює час останньої активності користувача (подовжує сеанс)."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевіряє, чи не минув дозволений час бездіяльності (timeout_sec)."""
        # Захист від некоректних (нульових або від'ємних) значень таймауту
        if timeout_sec <= 0:
            return False
        # Обчислюємо різницю між поточним часом та останньою активністю через timedelta
        elapsed = datetime.now(timezone.utc) - self.last_activity
        return elapsed < timedelta(seconds=timeout_sec)


# Декоратор @dataclass автоматично генерує методи __init__, __repr__ та __eq__.
# Ідеально підходить для зберігання структурованих записів без шаблонного коду.
@dataclass
class AuditEntry:
    """Модель одного запису в журналі безпеки."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал аудиту для фіксації подій безпеки (входи, помилки авторизації, виходи)."""

    def __init__(self):
        # Список для зберігання об'єктів AuditEntry
        self.logs = []

    def add_log(self, username: str, action: str) -> None:
        """Створює новий запис із поточним часом UTC. Паролі сюди НІКОЛИ не передаються."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        self.logs.append(entry)

    def show_all(self) -> None:
        """Виводить усі записи журналу у стандартному форматі часу ISO 8601."""
        for log in self.logs:
            print(f"[{log.timestamp.isoformat()}] {log.username}: {log.action}")


# Композиція об'єктів User, Session та AuditLog (принцип "Has-A" — Акаунт МАЄ юзера, сесію та лог)
class UserAccount:
    """Клас управління обліковим записом, що об'єднує користувача, його сесію та журнал аудиту."""

    SESSION_TIMEOUT_SEC = 900  # Таймаут сесії: 15 хвилин (900 секунд)

    def __init__(self, user: User, audit_log: AuditLog = None):
        self.user = user
        self.session = None  # Сесія створюється лише після успішного login()
        self.audit_log = audit_log if audit_log else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Автентифікація користувача: перевіряє статус, пароль та відкриває сесію."""
        # Якщо ім'я не збігається або користувач деактивований — фіксуємо невдалу спробу
        if self.user.username != username or not self.user.active:
            self.audit_log.add_log(username, "login_failure")
            return False

        # Перевіряємо криптографічний хеш пароля
        if self.user.check_password(password):
            self.session = Session(ip)  # Створюємо сеанс лише після успіху
            self.session.touch()  # Оновлюємо час активності
            self.audit_log.add_log(username, "login_success")
            return True
        else:
            self.audit_log.add_log(username, "login_failure")
            return False

    def is_authenticated(self) -> bool:
        """Перевіряє, чи авторизований користувач і чи не протермінована його сесія."""
        if not self.session:
            return False

        # Якщо сесія ще активна — оновлюємо час останньої дії (touch)
        if self.session.is_active(self.SESSION_TIMEOUT_SEC):
            self.session.touch()
            return True
        else:
            # Якщо час вийшов — примусово закриваємо сесію (невдала перевірка не подовжує сеанс)
            self.logout()
            return False

    def logout(self) -> None:
        """Завершує активний сеанс та записує подію виходу в журнал аудиту."""
        if self.session:
            self.audit_log.add_log(self.user.username, "logout")
            self.session = None

    def __getitem__(self, key: str):
        """Спеціальний метод для доступу до атрибутів через квадратні дужки: account['user']."""
        # Дозволяємо доступ лише до безпечних публічних компонентів (хеш і сіль пароля недоступні)
        if key == "user":
            return self.user
        elif key == "session":
            return self.session
        elif key == "audit_log":
            return self.audit_log
        else:
            raise KeyError(f"Невідомий ключ: {key}")

    def __setitem__(self, key: str, value):
        """Спеціальний метод для безпечної зміни атрибутів через account['user'] = new_user."""
        if key == "user":
            # Перевіряємо тип, щоб у поле user не записали випадковий рядок чи число
            if not isinstance(value, User):
                raise TypeError("Очікується об'єкт типу User")
            self.user = value
        else:
            raise KeyError(f"Не можна змінити атрибут: {key}")

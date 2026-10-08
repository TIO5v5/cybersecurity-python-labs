import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# Константа кількості ітерацій для PBKDF2
HASH_ITERATIONS = 100_000


class User:
    def __init__(
        self, username: str, email: str, role: str = "user", active: bool = True
    ):
        self.username = username
        self.role = role
        self.active = active
        self._email = None
        self.email = email  # Виклик setter-а

        # Приватні атрибути для пароля
        self.__password_hash = None
        self.__password_salt = None

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str):
        # Локальна частина: починається з літери, 3-64 символи (літери, цифри, крапка)
        # Далі @ і доменне ім'я з принаймні однією крапкою
        pattern = r"^[a-zA-Z][a-zA-Z0-9.]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError("Некоректний формат email адреси.")
        self._email = value

    def set_password(self, password: str) -> None:
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, HASH_ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        if not self.__password_hash or not self.__password_salt:
            return False

        test_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, HASH_ITERATIONS
        )
        # Використовуємо hmac.compare_digest для захисту від timing атак
        return hmac.compare_digest(self.__password_hash, test_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        return f"User({self.username}, Role: {self.role}, Active: {self.active})"


# Наслідування від User
class Admin(User):
    def __init__(
        self,
        username: str,
        email: str,
        active: bool = True,
        permissions: list | None = None,
    ):
        super().__init__(username, email, role="admin", active=active)
        self.permissions = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        return f"Admin({self.username}, Active: {self.active}, Permissions: {list(self.permissions)})"


class Session:
    def __init__(self, ip: str):
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            return False
        elapsed = datetime.now(timezone.utc) - self.last_activity
        return elapsed < timedelta(seconds=timeout_sec)


@dataclass
class AuditEntry:
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    def __init__(self):
        self.logs = []

    def add_log(self, username: str, action: str) -> None:
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc), username=username, action=action
        )
        self.logs.append(entry)

    def show_all(self) -> None:
        for log in self.logs:
            print(f"[{log.timestamp.isoformat()}] {log.username}: {log.action}")


# Композиція об'єктів User, Session та AuditLog
class UserAccount:
    SESSION_TIMEOUT_SEC = 900  # 15 хвилин

    def __init__(self, user: User, audit_log: AuditLog = None):
        self.user = user
        self.session = None
        self.audit_log = audit_log if audit_log else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if self.user.username != username or not self.user.active:
            self.audit_log.add_log(username, "login_failure")
            return False

        if self.user.check_password(password):
            self.session = Session(ip)
            self.audit_log.add_log(username, "login_success")
            return True
        else:
            self.audit_log.add_log(username, "login_failure")
            return False

    def is_authenticated(self) -> bool:
        if not self.session:
            return False

        if self.session.is_active(self.SESSION_TIMEOUT_SEC):
            self.session.touch()
            return True
        else:
            self.logout()  # Сесія закінчилась
            return False

    def logout(self) -> None:
        if self.session:
            self.audit_log.add_log(self.user.username, "logout")
            self.session = None

    def __getitem__(self, key: str):
        if key == "user":
            return self.user
        elif key == "session":
            return self.session
        elif key == "audit_log":
            return self.audit_log
        else:
            raise KeyError(f"Невідомий ключ: {key}")

    def __setitem__(self, key: str, value):
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Очікується об'єкт типу User")
            self.user = value
        else:
            raise KeyError(f"Не можна змінити атрибут: {key}")

"""Task 1: user accounts, sessions, and audit logging."""

import hashlib
import hmac
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from shared.student import STUDENT_NAME, VARIANT_NUMBER

PASSWORD_HASH_ITERATIONS = 100_000
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]{2,63}@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
SESSION_TIMEOUT_SEC = 900


class User:
    """A system user with a securely stored password."""

    def __init__(self, username: str, email: str, role: str, active: bool = True):
        self.username = username
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash = b""
        self.__password_salt = b""

    @property
    def email(self) -> str:
        """Return the user's validated email address."""
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        """Validate and store an email address."""
        if not isinstance(value, str) or not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("Invalid email address")
        self._email = value

    def set_password(self, password: str) -> None:
        """Create a new salted PBKDF2 password hash."""
        if not isinstance(password, str):
            raise TypeError("Password must be a string")
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PASSWORD_HASH_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        """Return whether *password* matches the stored hash."""
        if not isinstance(password, str) or not self.__password_hash:
            return False
        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PASSWORD_HASH_ITERATIONS,
        )
        return hmac.compare_digest(self.__password_hash, password_hash)

    def deactivate(self) -> None:
        """Deactivate the account."""
        self.active = False

    def __str__(self) -> str:
        return f"User(username={self.username}, role={self.role}, active={self.active})"


class Admin(User):
    """A user who can hold administrator permissions."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "admin",
        active: bool = True,
        permissions: set[str] | None = None,
    ):
        super().__init__(username, email, role, active)
        self.permissions = set() if permissions is None else set(permissions)

    def grant_permission(self, permission: str) -> None:
        """Grant an administrator permission."""
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        """Revoke an administrator permission if it exists."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Return whether the permission is granted."""
        return permission in self.permissions

    def __str__(self) -> str:
        permissions = ", ".join(sorted(self.permissions)) or "none"
        return f"Admin(username={self.username}, permissions={permissions})"


@dataclass
class Session:
    """An authenticated session and its activity timestamps."""

    ip: str
    login_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def touch(self) -> None:
        """Record activity at the current UTC time."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Return whether the session has not exceeded its timeout."""
        if timeout_sec <= 0:
            raise ValueError("Session timeout must be greater than zero")
        return datetime.now(timezone.utc) - self.last_activity <= timedelta(
            seconds=timeout_sec
        )


@dataclass
class AuditEntry:
    """One password-free account audit record."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Store account security events in memory."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def add_log(self, username: str, action: str) -> None:
        """Add an audit entry with a UTC timestamp."""
        self.entries.append(AuditEntry(datetime.now(timezone.utc), username, action))

    def show_all(self) -> list[AuditEntry]:
        """Print and return all audit entries."""
        for entry in self.entries:
            print(f"{entry.timestamp.isoformat()} | {entry.username} | {entry.action}")
        return self.entries.copy()


class UserAccount:
    """Compose a user, its current session, and audit log."""

    def __init__(self, user: User):
        if not isinstance(user, User):
            raise TypeError("user must be a User instance")
        self.user = user
        self.session: Session | None = None
        self.audit_log = AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Authenticate the user and create a session on success."""
        if (
            not self.user.active
            or username != self.user.username
            or not self.user.check_password(password)
        ):
            self.audit_log.add_log(username, "login_failure")
            return False

        self.session = Session(ip)
        self.session.touch()
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        """Return whether a non-expired session exists without refreshing it."""
        return self.session is not None and self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        """End the current session and record a logout event."""
        if self.session is not None:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str) -> User | Session | AuditLog | None:
        allowed = {"user", "session", "audit_log"}
        if key not in allowed:
            raise KeyError(key)
        return getattr(self, key)

    def __setitem__(self, key: str, value: User | Session | AuditLog | None) -> None:
        expected_types = {"user": User, "session": Session, "audit_log": AuditLog}
        if key not in expected_types:
            raise KeyError(key)
        if value is not None and not isinstance(value, expected_types[key]):
            raise TypeError(f"{key} has an invalid value type")
        if key in {"user", "audit_log"} and value is None:
            raise TypeError(f"{key} cannot be None")
        setattr(self, key, value)


def run_demo() -> None:
    """Run the non-interactive Task 1 demonstration."""
    user = User("student", "student@example.com", "user")
    user.set_password("SecurePassword123!")
    account = UserAccount(user)

    print("=== Laboratory Work #2: User Account Demo ===")
    print(f"Student: {STUDENT_NAME}")
    print(f"Variant: {VARIANT_NUMBER}")
    print(
        f"Successful login: {account.login('student', 'SecurePassword123!', '127.0.0.1')}"
    )
    print(f"Unsuccessful login: {account.login('student', 'incorrect', '127.0.0.1')}")
    user.email = "updated_student@example.org"
    print(f"Changed email: {user.email}")
    try:
        user.email = "not-an-email"
    except ValueError as error:
        print(f"Invalid email validation: {error}")

    admin = Admin("administrator", "admin@example.com")
    admin.grant_permission("manage_users")
    print(f"Administrator permission: {admin.has_permission('manage_users')}")
    if account.session is not None:
        account.session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 1)
    print(f"Session active after timeout: {account.is_authenticated()}")
    account.logout()
    print(f"Authenticated after logout: {account.is_authenticated()}")
    print("Audit log:")
    account.audit_log.show_all()

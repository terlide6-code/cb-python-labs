"""Task 3: Secure hashing, CSV database, JSON logging and exceptions."""

import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

MIN_PASSWORD_LENGTH = 10
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)
DATA_DIR = Path(__file__).resolve().parent / "data"
USERS_CSV_PATH = DATA_DIR / "users.csv"
LOG_JSON_PATH = DATA_DIR / "log.json"

users_to_register = (
    ("sysadmin02", "AdminPass2026!"),
    ("analyst234", "AnalystSafe77#"),
    ("developer567", "DevSecure2026@"),
    ("intern890", "InternAccess22$"),
    ("auditor445", "AuditTrail88!"),
    ("manager101", "ManagerKey55#"),
    ("support202", "SupportDesk44@"),
    ("tester303", "TestingPass33!"),
    ("guest404", "GuestPortal22#"),
    ("short_user", "short"),
)

users_db = []


class ValidationError(Exception):
    """Raised when password validation fails."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Generate a sha3_224 hash from password and salt."""
    if not password or not salt:
        raise ValueError("Password and salt must not be empty")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(f"Password is shorter than {MIN_PASSWORD_LENGTH} characters")

    value_to_hash = password + salt
    return hashlib.sha3_224(value_to_hash.encode()).hexdigest()


def create_user(username, password):
    """Create one user record with a password hash."""
    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value


def create_users(users_list):
    """Create users and save valid records to users.csv."""
    created_users = []
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    for username, password in users_list:
        try:
            created_users.append(create_user(username, password))
        except ValidationError as error:
            print(f"Skipping {username}: {error}")
        except ValueError as error:
            print(f"Skipping {username}: {error}")

    try:
        with USERS_CSV_PATH.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["username", "password_hash"])
            writer.writerows(created_users)
    except PermissionError as error:
        print(f"Permission error while writing users.csv: {error}")
    except OSError as error:
        print(f"I/O error while writing users.csv: {error}")

    return created_users


def read_users():
    """Read users.csv into a list of dictionaries."""
    loaded_users = []

    try:
        with USERS_CSV_PATH.open("r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            loaded_users = list(reader)
    except FileNotFoundError:
        print("users.csv was not found")
    except PermissionError as error:
        print(f"Permission error while reading users.csv: {error}")
    except OSError as error:
        print(f"I/O error while reading users.csv: {error}")

    return loaded_users


def print_users_table(users):
    """Print the user database as a simple table."""
    username_width = 16
    hash_width = 56
    header = f"{'Username':<{username_width}} {'Password hash':<{hash_width}}"

    print("Users database:")
    print(header)
    print("-" * len(header))

    for user in users:
        print(
            f"{user['username']:<{username_width}} "
            f"{user['password_hash']:<{hash_width}}"
        )


def read_log_events():
    """Read existing login events from log.json."""
    try:
        with LOG_JSON_PATH.open("r", encoding="utf-8") as file:
            events = json.load(file)
            if isinstance(events, list):
                return events
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        print("log.json contains invalid JSON, starting a new log")
    except PermissionError as error:
        print(f"Permission error while reading log.json: {error}")
    except OSError as error:
        print(f"I/O error while reading log.json: {error}")

    return []


def write_log_events(events):
    """Write login events to log.json."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    try:
        with LOG_JSON_PATH.open("w", encoding="utf-8") as file:
            json.dump(events, file, indent=4)
    except PermissionError as error:
        print(f"Permission error while writing log.json: {error}")
    except OSError as error:
        print(f"I/O error while writing log.json: {error}")


def log_event(function):
    """Decorator that logs every login attempt."""

    @functools.wraps(function)
    def wrapper(username, password):
        result = "failure"

        try:
            login_success = function(username, password)
            if login_success:
                result = "success"
            return login_success
        finally:
            event = {
                "event": "login",
                "user": username,
                "result": result,
                "timestamp": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "args": [],
                "kwargs": {},
            }
            events = read_log_events()
            events.append(event)
            write_log_events(events)

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Authenticate a user against users_db."""
    if not username or not password:
        raise ValueError("Username and password must not be empty")

    for user in users_db:
        if user["username"] == username:
            try:
                password_hash = generate_hash(password, PERSONAL_SALT)
            except ValidationError:
                return False
            return password_hash == user["password_hash"]

    return False


def demonstrate_login(username, password):
    """Run one login attempt and print the result."""
    try:
        if login(username, password):
            print(f"Login for {username}: success")
        else:
            print(f"Login for {username}: failure")
    except ValueError as error:
        print(f"Login for {username}: {error}")


def main():
    """Run Task 3 for Variant 2."""
    global users_db

    print("Laboratory Work #1 - Task 3")
    print(f"Student: {STUDENT_NAME}")
    print(f"Group: {GROUP_NAME}")
    print(f"Variant: {VARIANT_NUMBER}")
    print(f"Personal salt: {PERSONAL_SALT}")
    print()

    create_users(users_to_register)
    users_db = read_users()
    print_users_table(users_db)
    print()

    demonstrate_login("sysadmin02", "AdminPass2026!")
    demonstrate_login("sysadmin02", "WrongPassword99!")
    demonstrate_login("missing_user", "MissingPass2026!")


if __name__ == "__main__":
    main()

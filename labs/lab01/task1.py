"""Task 1: Password strength analyzer for laboratory work #1."""

import os
import random
import sys

sys.path.append (os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

PASSWORDS = [
    "Hello123!",
    "simple",
    "CompL3x@Pass",
    "password",
    "Str0ng#2023",
    "weak",
    "MySecur3!",
    "12345",
    "Advanced@1",
    "basic",
]

CRITERIA = {
    "min_length": 10,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {
    "password",
    "simple",
    "weak",
    "basic",
    "12345",
    "hello",
}


def has_digit(password):
    """Return True if the password contains at least one digit."""
    return any(char.isdigit() for char in password)


def has_upper(password):
    """Return True if the password contains at least one uppercase letter."""
    return any(char.isupper() for char in password)


def has_special(password):
    """Return True if the password contains at least one special character."""
    return any(not char.isalnum() for char in password)


def count_character_criteria(password):
    """Count how many character-group criteria the password satisfies."""
    checks = [
        has_digit(password),
        has_upper(password),
        has_special(password),
    ]
    return sum(checks)


def is_forbidden(password):
    """Return True if the password is forbidden by list or length."""
    return (
        password in FORBIDDEN_PASSWORDS
        or len(password) < CRITERIA["min_length"]
    )


def classify_password(password, all_passwords):
    """Classify one password using the laboratory strength rules."""
    if is_forbidden(password):
        return "Forbidden"

    character_criteria_count = count_character_criteria(password)
    all_character_criteria = character_criteria_count == 3
    min_length = CRITERIA["min_length"]
    occurrences = all_passwords.count(password)

    if all_character_criteria and len(password) >= min_length + 4:
        if occurrences == 1:
            return "Very Strong"
        return "Strong"

    if all_character_criteria:
        return "Strong"

    if 0 < character_criteria_count < 3:
        return "Medium"

    return "Weak"


def add_random_duplicates(passwords):
    """Append duplicates of three randomly selected original passwords."""
    original_count = len(passwords)
    random_indexes = random.sample(range(original_count), 3)

    for index in random_indexes:
        passwords.append(passwords[index])

    return random_indexes


def print_table(passwords):
    """Print a readable table with password analysis results."""
    header = (
        f"{'Password':<16} "
        f"{'Length':<6} "
        f"{'Digit':<5} "
        f"{'Uppercase':<9} "
        f"{'Special':<7} "
        f"{'Occurrences':<11} "
        f"{'Strength':<12}"
    )

    print(header)
    print("-" * len(header))

    for password in passwords:
        print(
            f"{password:<16} "
            f"{len(password):<6} "
            f"{has_digit(password)!s:<5} "
            f"{has_upper(password)!s:<9} "
            f"{has_special(password)!s:<7} "
            f"{passwords.count(password):<11} "
            f"{classify_password(password, passwords):<12}"
        )


def run_task1():
    """Run Task 1 for Variant 2."""
    passwords = PASSWORDS.copy()
    duplicate_indexes = add_random_duplicates(passwords)

    print("Laboratory Work #1 - Task 1")
    print(f"Student: {STUDENT_NAME}")
    print(f"Group: {GROUP_NAME}")
    print(f"Variant: {VARIANT_NUMBER}")
    print()
    print(f"Random indexes used for duplicates: {duplicate_indexes}")
    print()
    print_table(passwords)


if __name__ == "__main__":
    run_task1()

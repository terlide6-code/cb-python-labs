"""Task 2: Multilevel access control system for laboratory work #1."""
import os
import sys

sys.path.append (os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

USERS = {
    "sysadmin02": {
        "role": "system_admin",
        "clearance": 4,
        "department": "Infrastructure",
        "active": True,
    },
    "analyst234": {
        "role": "security_analyst",
        "clearance": 3,
        "department": "SOC",
        "active": True,
    },
    "developer567": {
        "role": "developer",
        "clearance": 2,
        "department": "Development",
        "active": True,
    },
    "intern890": {
        "role": "intern",
        "clearance": 1,
        "department": "HR",
        "active": True,
    },
    "external123": {
        "role": "external",
        "clearance": 1,
        "department": "Vendor",
        "active": False,
    },
}

RESOURCES = [
    ("prod_database", 4),
    ("dev_environment", 2),
    ("documentation", 1),
    ("source_code", 3),
    ("server_configs", 4),
    ("test_data", 2),
    ("compliance_docs", 3),
    ("system_logs", 4),
    ("project_files", 2),
    ("public_wiki", 1),
]

SECURITY_LEVELS = (
    "Open",
    "Internal",
    "Restricted",
    "Top Secret",
)

BLOCKED_USERS = {
    "external123",
    "old_account",
    "test_user",
}


def get_security_level_name(level):
    """Return a text name for a numeric security level."""
    return SECURITY_LEVELS[level - 1]


def print_resources():
    """Print all resources with text security level names."""
    print("Resources:")

    for resource_name, security_level in RESOURCES:
        level_name = get_security_level_name(security_level)
        print(f"{resource_name}: {level_name}")


def check_access(username, resource_level):
    """Check whether a user can access a resource."""
    if username not in USERS:
        return False, "User not found"

    if username in BLOCKED_USERS:
        return False, "User is blocked"

    user = USERS[username]

    if not user["active"]:
        return False, "Account inactive"

    if user["clearance"] >= resource_level:
        return True, ""

    return False, "Insufficient clearance"


def print_access_result(username, resource_name, resource_level):
    """Print one access-check result."""
    allowed, reason = check_access(username, resource_level)

    if allowed:
        print(f"user={username} resource={resource_name} -> ALLOW")
    else:
        print(f"user={username} resource={resource_name} -> DENY ({reason})")


def print_access_checks():
    """Check access for every user against every resource."""
    print("Access checks:")

    for username in USERS:
        for resource_name, resource_level in RESOURCES:
            print_access_result(username, resource_name, resource_level)


def run_task2():
    """Run Task 2 for Variant 2."""
    print("Laboratory Work #1 - Task 2")
    print(f"Student: {STUDENT_NAME}")
    print(f"Group: {GROUP_NAME}")
    print(f"Variant: {VARIANT_NUMBER}")
    print()

    print_resources()
    print()
    print_access_checks()
    print()



if __name__ == "__main__":
    run_task2()

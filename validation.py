"""Input rules for usernames and passwords."""

import re

USERNAME_RULE = re.compile(r"^[A-Za-z0-9_]{3,20}$")

# A tiny sample list. Real systems check against lists of thousands.
COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789",
    "qwerty123", "iloveyou", "admin123", "welcome1", "letmein", "abc12345",
}


def validate_username(username: str) -> list[str]:
    """Return a list of problems. An empty list means the username is fine."""
    if not USERNAME_RULE.match(username):
        return ["3 to 20 characters, using only letters, numbers or underscores"]
    return []


def validate_password(password: str, username: str = "") -> list[str]:
    """Return a list of problems. An empty list means the password is fine."""
    problems = []
    if len(password) < 10:
        problems.append("at least 10 characters")
    if not re.search(r"[a-z]", password):
        problems.append("a lowercase letter")
    if not re.search(r"[A-Z]", password):
        problems.append("an uppercase letter")
    if not re.search(r"\d", password):
        problems.append("a number")
    if not re.search(r"[^A-Za-z0-9]", password):
        problems.append("a symbol")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("to not be a commonly used password")
    if username and username.lower() in password.lower():
        problems.append("to not contain your username")
    return problems
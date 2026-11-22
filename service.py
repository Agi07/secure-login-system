"""The actions a user can take: registering (login comes next)."""

from auth import hash_password
from database import DB_FILE, add_user, init_db
from validation import validate_password, validate_username


def register_user(username: str, password: str, db_file: str = DB_FILE):
    """Try to create an account. Returns (success, message)."""
    username = username.strip()

    problems = validate_username(username)
    if problems:
        return False, "Username must be " + "; ".join(problems) + "."

    problems = validate_password(password, username)
    if problems:
        return False, "Password needs: " + ", ".join(problems) + "."

    if not add_user(username, hash_password(password), db_file):
        return False, "That username is already taken."

    return True, "Account created."


if __name__ == "__main__":
    import os

    demo = "demo.db"
    init_db(demo)
    attempts = [
        ("moagi", "short"),
        ("moagi", "alllowercase1!"),
        ("mo", "Str0ng!Password"),
        ("moagi", "Moagi!Secure99"),
        ("moagi", "Tr1cky!Lock#42"),
        ("moagi", "Tr1cky!Lock#42"),
    ]
    for username, password in attempts:
        ok, message = register_user(username, password, demo)
        print(f"{username!r} / {password!r} -> {ok}: {message}")
    os.remove(demo)
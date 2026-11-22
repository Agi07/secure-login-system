"""The actions a user can take: register and log in."""

import time

from auth import hash_password, verify_password
from database import DB_FILE, add_user, get_user, init_db, update_attempts
from validation import validate_password, validate_username

MAX_ATTEMPTS = 5      # wrong passwords allowed before the account locks
LOCK_SECONDS = 300    # how long the lock lasts (5 minutes)

# Used to keep response time similar when the username does not exist.
DUMMY_HASH = hash_password("dummy-password-for-timing")


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


def login_user(username: str, password: str, db_file: str = DB_FILE, now=None):
    """Try to log in. Returns (success, message)."""
    now = time.time() if now is None else now
    username = username.strip()
    user = get_user(username, db_file)

    if user is None:
        # Do the same slow hashing work, so an attacker cannot tell
        # from the response time whether the username exists.
        verify_password(password, DUMMY_HASH)
        return False, "Invalid username or password."

    if user["locked_until"] > now:
        minutes = int((user["locked_until"] - now) // 60) + 1
        return False, f"Account locked. Try again in about {minutes} minute(s)."

    if verify_password(password, user["password_hash"]):
        update_attempts(username, 0, 0, db_file)  # success clears the counter
        return True, "Login successful."

    attempts = user["failed_attempts"] + 1
    if attempts >= MAX_ATTEMPTS:
        update_attempts(username, 0, now + LOCK_SECONDS, db_file)
        return False, "Too many failed attempts. Account locked for 5 minutes."

    update_attempts(username, attempts, 0, db_file)
    # Same message as an unknown username, on purpose.
    return False, "Invalid username or password."


if __name__ == "__main__":
    import os

    demo = "demo.db"
    init_db(demo)
    print(register_user("moagi", "Tr1cky!Lock#42", demo))

    start = time.time()
    for i in range(1, 6):
        print(f"Wrong attempt {i}:", login_user("moagi", "wrong", demo, now=start))

    print("Correct password while locked:",
          login_user("moagi", "Tr1cky!Lock#42", demo, now=start + 10))
    print("Correct password after 6 minutes:",
          login_user("moagi", "Tr1cky!Lock#42", demo, now=start + 360))
    print("Unknown user:", login_user("nobody", "whatever", demo, now=start))
    os.remove(demo)
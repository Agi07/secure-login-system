"""SQLite storage for the secure login system."""

import sqlite3
from contextlib import closing

DB_FILE = "users.db"


def get_connection(db_file: str = DB_FILE) -> sqlite3.Connection:
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row  # lets us read columns by name
    return conn


def init_db(db_file: str = DB_FILE) -> None:
    """Create the users table if it does not exist yet."""
    with closing(get_connection(db_file)) as conn:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until REAL NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )


def add_user(username: str, password_hash: str, db_file: str = DB_FILE) -> bool:
    """Save a new user. Returns False if the username is already taken."""
    try:
        with closing(get_connection(db_file)) as conn:
            with conn:
                # The ? placeholders keep user input separate from the SQL command.
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash),
                )
        return True
    except sqlite3.IntegrityError:
        return False


def get_user(username: str, db_file: str = DB_FILE):
    """Return the user's row, or None if there is no such user."""
    with closing(get_connection(db_file)) as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


if __name__ == "__main__":
    import os

    from auth import hash_password

    demo = "demo.db"
    init_db(demo)
    print("Add moagi:", add_user("moagi", hash_password("Secret123!"), demo))
    print("Add moagi again:", add_user("moagi", hash_password("Other456!"), demo))
    user = get_user("moagi", demo)
    print("Found:", user["username"], "| stored hash starts with:", user["password_hash"][:25])
    print("Find nobody:", get_user("nobody", demo))

    # Try a classic SQL injection attack. It should find nothing.
    print("Injection attempt:", get_user("' OR '1'='1", demo))
    os.remove(demo)
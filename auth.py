"""Password hashing and verification for the secure login system."""

import hashlib
import hmac
import secrets

# How many times the hash is repeated. A high number makes each guess slow,
# which makes brute-force attacks expensive for an attacker.
ITERATIONS = 600_000


def hash_password(password: str) -> str:
    """Turn a password into a safe string to store. Never store the password itself."""
    salt = secrets.token_bytes(16)  # random, different for every user
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ITERATIONS
    )
    return f"{ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Check a login attempt against the stored string."""
    iterations, salt_hex, digest_hex = stored.split("$")
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        int(iterations),
    )
    # compare_digest takes the same time however many characters match,
    # which stops timing attacks.
    return hmac.compare_digest(digest.hex(), digest_hex)


if __name__ == "__main__":
    stored = hash_password("MyPassword123!")
    print("Stored value:", stored)
    print("Correct password:", verify_password("MyPassword123!", stored))
    print("Wrong password:", verify_password("wrong", stored))
    print("Same password hashed again:", hash_password("MyPassword123!"))
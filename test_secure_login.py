"""Automated tests for the secure login system. Run: python -m unittest -v"""

import logging
import os
import tempfile
import unittest
from unittest.mock import patch

logging.disable(logging.CRITICAL)  # keeps test runs out of security.log

import auth
from database import get_user, init_db
from service import LOCK_SECONDS, MAX_ATTEMPTS, login_user, register_user
from validation import validate_password, validate_username

GOOD_PASSWORD = "Tr1cky!Lock#42"


class BaseTest(unittest.TestCase):
    """Gives every test a fast hash setting and its own temporary database."""

    def setUp(self):
        # Fewer hash rounds so the tests run quickly. Real use stays at 600,000.
        patcher = patch("auth.ITERATIONS", 1000)
        patcher.start()
        self.addCleanup(patcher.stop)

        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.addCleanup(os.remove, self.db)
        init_db(self.db)


class TestHashing(BaseTest):
    def test_password_not_in_hash(self):
        stored = auth.hash_password(GOOD_PASSWORD)
        self.assertNotIn(GOOD_PASSWORD, stored)

    def test_correct_password_verifies(self):
        stored = auth.hash_password(GOOD_PASSWORD)
        self.assertTrue(auth.verify_password(GOOD_PASSWORD, stored))

    def test_wrong_password_rejected(self):
        stored = auth.hash_password(GOOD_PASSWORD)
        self.assertFalse(auth.verify_password("wrong", stored))

    def test_same_password_gives_different_hashes(self):
        self.assertNotEqual(
            auth.hash_password(GOOD_PASSWORD), auth.hash_password(GOOD_PASSWORD)
        )


class TestValidation(BaseTest):
    def test_strong_password_accepted(self):
        self.assertEqual(validate_password(GOOD_PASSWORD, "moagi"), [])

    def test_short_password_rejected(self):
        self.assertIn("at least 10 characters", validate_password("Ab1!"))

    def test_each_missing_type_reported(self):
        self.assertIn("an uppercase letter", validate_password("alllowercase1!"))
        self.assertIn("a lowercase letter", validate_password("ALLUPPERCASE1!"))
        self.assertIn("a number", validate_password("NoNumbers!Here"))
        self.assertIn("a symbol", validate_password("NoSymbols1Here"))

    def test_password_with_username_rejected(self):
        self.assertIn(
            "to not contain your username",
            validate_password("Moagi!Secure99", "moagi"),
        )

    def test_common_password_rejected(self):
        self.assertIn(
            "to not be a commonly used password", validate_password("password123")
        )

    def test_valid_usernames_accepted(self):
        for name in ["moagi", "Moagi_99", "abc"]:
            self.assertEqual(validate_username(name), [], name)

    def test_invalid_usernames_rejected(self):
        for name in ["ab", "has space", "a" * 21, "semi;colon", "' OR '1'='1"]:
            self.assertNotEqual(validate_username(name), [], name)


class TestService(BaseTest):
    def test_register_ok(self):
        ok, _ = register_user("moagi", GOOD_PASSWORD, self.db)
        self.assertTrue(ok)

    def test_register_duplicate_username(self):
        register_user("moagi", GOOD_PASSWORD, self.db)
        ok, message = register_user("moagi", "Another!Pass77", self.db)
        self.assertFalse(ok)
        self.assertIn("already taken", message)

    def test_register_weak_password(self):
        ok, _ = register_user("moagi", "weak", self.db)
        self.assertFalse(ok)
        self.assertIsNone(get_user("moagi", self.db))

    def test_password_not_stored_in_database(self):
        register_user("moagi", GOOD_PASSWORD, self.db)
        stored = get_user("moagi", self.db)["password_hash"]
        self.assertNotIn(GOOD_PASSWORD, stored)

    def test_login_ok(self):
        register_user("moagi", GOOD_PASSWORD, self.db)
        ok, _ = login_user("moagi", GOOD_PASSWORD, self.db, now=1000.0)
        self.assertTrue(ok)

    def test_wrong_password_same_message_as_unknown_user(self):
        register_user("moagi", GOOD_PASSWORD, self.db)
        _, wrong_pw = login_user("moagi", "wrong", self.db, now=1000.0)
        _, no_user = login_user("nobody", "wrong", self.db, now=1000.0)
        self.assertEqual(wrong_pw, no_user)

    def test_lockout_after_max_failed_attempts(self):
        register_user("moagi", GOOD_PASSWORD, self.db)
        for _ in range(MAX_ATTEMPTS - 1):
            ok, _ = login_user("moagi", "wrong", self.db, now=1000.0)
            self.assertFalse(ok)
        ok, message = login_user("moagi", "wrong", self.db, now=1000.0)
        self.assertFalse(ok)
        self.assertIn("locked", message.lower())

    def test_locked_account_rejects_correct_password(self):
        register_user("moagi", GOOD_PASSWORD, self.db)
        for _ in range(MAX_ATTEMPTS):
            login_user("moagi", "wrong", self.db, now=1000.0)
        ok, _ = login_user("moagi", GOOD_PASSWORD, self.db, now=1010.0)
        self.assertFalse(ok)

    def test_lock_expires(self):
        register_user("moagi", GOOD_PASSWORD, self.db)
        for _ in range(MAX_ATTEMPTS):
            login_user("moagi", "wrong", self.db, now=1000.0)
        later = 1000.0 + LOCK_SECONDS + 1
        ok, _ = login_user("moagi", GOOD_PASSWORD, self.db, now=later)
        self.assertTrue(ok)

    def test_success_resets_counter(self):
        register_user("moagi", GOOD_PASSWORD, self.db)
        for _ in range(MAX_ATTEMPTS - 2):
            login_user("moagi", "wrong", self.db, now=1000.0)
        login_user("moagi", GOOD_PASSWORD, self.db, now=1001.0)
        # After a success, a few more failures must not lock the account.
        for _ in range(MAX_ATTEMPTS - 1):
            ok, message = login_user("moagi", "wrong", self.db, now=1002.0)
            self.assertNotIn("locked", message.lower())

    def test_sql_injection_fails(self):
        register_user("moagi", GOOD_PASSWORD, self.db)
        for name in ["' OR '1'='1", "moagi' --", "moagi'; DROP TABLE users; --"]:
            ok, _ = login_user(name, "anything", self.db, now=1000.0)
            self.assertFalse(ok, name)
        self.assertIsNotNone(get_user("moagi", self.db))  # table is still intact


if __name__ == "__main__":
    unittest.main()
"""
Unit tests for bcrypt password hashing, authentication flow,
login attempt monitoring, and account lockout mechanisms.
"""

import os
import unittest
import tempfile
from config import Config

# Point to temporary test database
test_db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
test_db_path = test_db_file.name
test_db_file.close()

# Override config for testing
Config.DATABASE_PATH = test_db_path
Config.BCRYPT_ROUNDS = 4  # Fast for tests

from database import init_db, get_user_by_username
from security.auth import (
    hash_password,
    verify_password,
    register_user_account,
    authenticate_user,
    update_password
)

class TestAuthSecurity(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(test_db_path):
            try:
                os.remove(test_db_path)
            except Exception:
                pass

    def test_bcrypt_hashing_and_salting(self):
        pwd = "TestSecur3Password!"
        hash1 = hash_password(pwd)
        hash2 = hash_password(pwd)
        
        # Bcrypt must produce different unique salts even for identical passwords
        self.assertNotEqual(hash1, hash2)
        
        # Both must verify correctly
        self.assertTrue(verify_password(pwd, hash1))
        self.assertTrue(verify_password(pwd, hash2))
        self.assertFalse(verify_password("WrongPassword123", hash1))

    def test_user_registration(self):
        success, msg, user_id = register_user_account(
            username="unit_user",
            email="unit@test.local",
            password="StrongUnitPass#2026!"
        )
        self.assertTrue(success)
        self.assertIsNotNone(user_id)

        user = get_user_by_username("unit_user")
        self.assertIsNotNone(user)
        self.assertEqual(user["email"], "unit@test.local")
        self.assertGreater(user["password_score"], 50)

    def test_lockout_after_five_failed_attempts(self):
        # Register a target user for lockout test
        reg_ok, _, _ = register_user_account(
            username="lockout_target",
            email="lockout@test.local",
            password="ValidPassword#999"
        )
        self.assertTrue(reg_ok)

        # 1st to 4th failed attempts
        for attempt_num in range(1, 5):
            success, user, message = authenticate_user(
                username="lockout_target",
                password="IncorrectPassword!",
                ip_address="192.168.1.50",
                user_agent="TestRunner"
            )
            self.assertFalse(success)
            self.assertIn(f"{5 - attempt_num} attempt", message)

        # 5th failed attempt: Must trigger lockout
        success, user, message = authenticate_user(
            username="lockout_target",
            password="IncorrectPassword!",
            ip_address="192.168.1.50",
            user_agent="TestRunner"
        )
        self.assertFalse(success)
        self.assertIn("Account locked!", message)

        # 6th attempt with CORRECT password: Must still be rejected because account is locked
        locked_success, locked_user, locked_msg = authenticate_user(
            username="lockout_target",
            password="ValidPassword#999",
            ip_address="192.168.1.50",
            user_agent="TestRunner"
        )
        self.assertFalse(locked_success)
        self.assertIn("temporarily locked", locked_msg)

    def test_successful_auth_resets_failures(self):
        reg_ok, _, user_id = register_user_account(
            username="reset_user",
            email="reset@test.local",
            password="ResetPassword#777"
        )
        self.assertTrue(reg_ok)

        # 2 failed attempts
        authenticate_user("reset_user", "badpass", "10.0.0.1", "Test")
        authenticate_user("reset_user", "badpass", "10.0.0.1", "Test")

        user_before = get_user_by_username("reset_user")
        self.assertEqual(user_before["failed_attempts"], 2)

        # Successful login
        ok, user, msg = authenticate_user("reset_user", "ResetPassword#777", "10.0.0.1", "Test")
        self.assertTrue(ok)

        user_after = get_user_by_username("reset_user")
        self.assertEqual(user_after["failed_attempts"], 0)

if __name__ == '__main__':
    unittest.main()

"""
End-to-end integration tests for Flask web routes and REST API endpoints.
"""

import os
import unittest
import tempfile
from config import Config

# Point to temporary test database
test_db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
test_db_path = test_db_file.name
test_db_file.close()

Config.DATABASE_PATH = test_db_path
Config.BCRYPT_ROUNDS = 4

from app import app
from database import init_db
from security.auth import register_user_account

class TestFlaskRoutes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()
        # Seed test admin and standard user
        register_user_account("test_admin", "admin@test.local", "AdminMasterKey#2026!", role="admin")
        register_user_account("test_regular", "user@test.local", "UserNormalKey#2026!", role="user")

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(test_db_path):
            try:
                os.remove(test_db_path)
            except Exception:
                pass

    def setUp(self):
        self.client = app.test_client()

    def test_public_pages_load(self):
        # Home
        res_home = self.client.get('/')
        self.assertEqual(res_home.status_code, 200)
        self.assertIn(b"Password Analyzer", res_home.data)

        # Standalone Analyzer
        res_analyzer = self.client.get('/analyzer')
        self.assertEqual(res_analyzer.status_code, 200)
        self.assertIn(b"Estimated Time to Crack", res_analyzer.data)

        # Login page
        res_login = self.client.get('/login')
        self.assertEqual(res_login.status_code, 200)
        self.assertIn(b"Secure Sign In", res_login.data)

        # Register page
        res_reg = self.client.get('/register')
        self.assertEqual(res_reg.status_code, 200)
        self.assertIn(b"Create Secure Account", res_reg.data)

    def test_api_analyze_password(self):
        response = self.client.post('/api/analyze-password', json={
            "password": "Password123!"
        })
        self.assertEqual(response.status_code, 200)
        json_data = response.get_json()
        self.assertIn("score", json_data)
        self.assertIn("category", json_data)
        self.assertIn("effective_entropy", json_data)
        self.assertIn("crack_times", json_data)
        self.assertIn("patterns", json_data)
        self.assertTrue(json_data["dictionary_analysis"]["is_substring_match"])

    def test_api_generate_password(self):
        response = self.client.get('/api/generate-password?length=18&upper=true&digits=true&symbols=true')
        self.assertEqual(response.status_code, 200)
        json_data = response.get_json()
        self.assertEqual(len(json_data["password"]), 18)
        self.assertGreaterEqual(json_data["analysis"]["score"], 60)

    def test_user_login_and_dashboard_access(self):
        # Login with valid credentials
        login_res = self.client.post('/login', data={
            "username": "test_regular",
            "password": "UserNormalKey#2026!"
        }, follow_redirects=True)
        self.assertEqual(login_res.status_code, 200)
        self.assertIn(b"Account Security Dashboard", login_res.data)

        # Check authenticated dashboard
        dash_res = self.client.get('/dashboard')
        self.assertEqual(dash_res.status_code, 200)
        self.assertIn(b"test_regular", dash_res.data)

        # Regular user accessing admin SOC should be denied
        admin_res = self.client.get('/admin', follow_redirects=True)
        self.assertIn(b"Access denied", admin_res.data)

    def test_admin_access_and_stats_api(self):
        # Sign in as admin
        self.client.post('/login', data={
            "username": "test_admin",
            "password": "AdminMasterKey#2026!"
        }, follow_redirects=True)

        # Admin page access
        admin_res = self.client.get('/admin')
        self.assertEqual(admin_res.status_code, 200)
        self.assertIn(b"Security Operations Center (SOC)", admin_res.data)

        # Security stats API
        stats_res = self.client.get('/api/security-stats')
        self.assertEqual(stats_res.status_code, 200)
        stats_json = stats_res.get_json()
        self.assertIn("total_users", stats_json)
        self.assertIn("total_attempts", stats_json)

if __name__ == '__main__':
    unittest.main()

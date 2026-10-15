import importlib
import os
import sys
import tempfile
import types
from cryptography.fernet import Fernet
import unittest
from unittest.mock import patch

# Do not require a real camera, Discord webhook, or local secret file.
sys.modules.setdefault("cv2", types.ModuleType("cv2"))
config = types.ModuleType("config")
config.SECRET_KEY = "test-only-session-key"
config.ADMIN_PASSWORD = "test-password"
config.DISCORD_WEBHOOK_URL = "https://example.invalid/webhook"
sys.modules["config"] = config
os.environ["ABOUTCAM_FERNET_KEY"] = Fernet.generate_key().decode("ascii")
os.environ["ABOUTCAM_INVITE_CODE"] = "test-invite"


with tempfile.TemporaryDirectory() as work:
    old = os.getcwd()
    os.chdir(work)
    try:
        app_module = importlib.import_module("app")
    finally:
        os.chdir(old)

class SecurityTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        app_module.login_failures.clear()
        app_module.known_ips.clear()
        app_module.system_status["ip_monitoring"] = True
        app_module.system_status["motion_detection"] = False
        self.client = app_module.app.test_client()

    def login(self):
        with patch.object(app_module.accounts, "authenticate", return_value=1):
            response = self.client.post("/login", data={"username": "tester", "password": "test-password"})
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as sess:
            return sess["csrf_token"]

    def test_unauthenticated_toggle_denied(self):
        r = self.client.post("/toggle", json={"feature": "ip_monitoring"})
        self.assertEqual(r.status_code, 401)

    def test_login_failure_and_lockout(self):
        with patch.object(app_module.threading, "Thread") as thread:
            for _ in range(5):
                r = self.client.post("/login", data={"username": "tester", "password": "wrong"})
                self.assertEqual(r.status_code, 200)
            r = self.client.post("/login", data={"username": "tester", "password": "test-password"})
            self.assertIn("시도 횟수 초과".encode("utf-8"), r.data)
        self.assertEqual(app_module.login_failures["127.0.0.1"][0], 5)

    def test_csrf_and_logout(self):
        token = self.login()
        self.assertEqual(self.client.post("/toggle", json={"feature": "ip_monitoring"}).status_code, 403)
        self.assertEqual(self.client.post("/toggle", json={"feature": "ip_monitoring"}, headers={"X-CSRF-Token": "wrong"}).status_code, 403)
        ok = self.client.post("/toggle", json={"feature": "ip_monitoring"}, headers={"X-CSRF-Token": token})
        self.assertEqual(ok.status_code, 200)
        self.assertFalse(ok.json["status"])
        self.assertEqual(self.client.post("/logout").status_code, 403)
        self.assertEqual(self.client.post("/logout", data={"csrf_token": token}).status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_ip_monitoring_authenticated_only(self):
        with patch.object(app_module.threading, "Thread") as thread, patch.object(app_module, "save_known_ips"):
            self.client.get("/", environ_overrides={"REMOTE_ADDR": "198.51.100.2"})
            self.assertEqual(len(app_module.known_ips), 0)
            self.login()
            self.client.get("/", environ_overrides={"REMOTE_ADDR": "198.51.100.2"})
            self.client.get("/", environ_overrides={"REMOTE_ADDR": "198.51.100.2"})
            self.assertIn("198.51.100.2", app_module.known_ips)
            self.assertEqual(thread.call_count, 1)

    def test_registration_requires_invite(self):
        response = self.client.post("/register", data={"username": "tester", "password": "very-long-password", "invite_code": "wrong", "webhook": "https://discord.com/api/webhooks/123/secret"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("초대 코드".encode("utf-8"), response.data)

    def test_untrusted_forwarded_header(self):
        with app_module.app.test_request_context("/", environ_base={"REMOTE_ADDR": "198.51.100.3"}, headers={"X-Forwarded-For": "203.0.113.9"}):
            with patch.dict(os.environ, {"TRUSTED_PROXIES": ""}):
                self.assertEqual(app_module.get_client_ip(), "198.51.100.3")
            with patch.dict(os.environ, {"TRUSTED_PROXIES": "198.51.100.3"}):
                self.assertEqual(app_module.get_client_ip(), "203.0.113.9")

if __name__ == "__main__":
    unittest.main()

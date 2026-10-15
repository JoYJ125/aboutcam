"""Isolated security tests; no real camera or outbound Discord traffic."""
import importlib
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from cryptography.fernet import Fernet

sys.modules.setdefault("cv2", types.ModuleType("cv2"))
config = types.ModuleType("config")
config.SECRET_KEY = "test-session-secret"
sys.modules["config"] = config
os.environ["ABOUTCAM_FERNET_KEY"] = Fernet.generate_key().decode()
os.environ["ABOUTCAM_INVITE_CODE"] = "test-invite"

with tempfile.TemporaryDirectory() as folder:
    with patch.dict(os.environ, {"ABOUTCAM_USERS_DB": os.path.join(folder, "initial.db")}):
        app_module = importlib.import_module("app")

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path = os.path.join(self.tmp.name, "users.db")
        self.patches = [
            patch.object(app_module.accounts, "DB_PATH", path),
            patch.object(app_module.ip_access, "DB_PATH", path),
            patch.object(app_module.threading, "Thread"),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        app_module.accounts.init_db()
        app_module.ip_access.init_db()
        app_module.app.config["TESTING"] = True
        app_module.login_failures.clear()
        app_module.system_status["motion_detection"] = False
        self.client = app_module.app.test_client()
        self.uid = app_module.accounts.create_user("member01", "strong-password-123",
            "https://discord.com/api/webhooks/123456/token")

    def login(self, ip="127.0.0.1"):
        r = self.client.post("/login", data={"username": "member01", "password": "strong-password-123"},
                             environ_overrides={"REMOTE_ADDR": ip})
        self.assertEqual(r.status_code, 302)
        with self.client.session_transaction() as sess:
            return sess["csrf_token"]

    def test_login_required(self):
        self.assertEqual(self.client.get("/").status_code, 302)
        self.assertEqual(self.client.post("/toggle", json={"feature": "motion_detection"}).status_code, 401)

    def test_loopback_bootstrap_and_management(self):
        token = self.login()
        self.assertEqual(self.client.get("/").status_code, 200)
        entries = app_module.ip_access.list_ips(self.uid)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["name"], "관리자 로컬 PC")
        self.assertEqual(self.client.get("/ip-management").status_code, 200)
        self.assertEqual(self.client.post("/ip-management", data={"ip": "127.0.0.1", "name": "PC", "allowed": "0",
            "csrf_token": token}).status_code, 200)
        self.assertTrue(app_module.ip_access.list_ips(self.uid)[0]["allowed"])
        self.assertEqual(self.client.post("/ip-management", data={"ip": "127.0.0.1", "name": "내 PC", "allowed": "1",
            "csrf_token": token}).status_code, 302)
        self.assertEqual(app_module.ip_access.list_ips(self.uid)[0]["name"], "내 PC")

    def test_unknown_ip_denied_and_alert_throttled(self):
        self.login()
        with patch.object(app_module.threading, "Thread") as thread:
            for _ in range(2):
                r = self.client.get("/video_feed", environ_overrides={"REMOTE_ADDR": "198.51.100.10"})
                self.assertEqual(r.status_code, 403)
            self.assertEqual(thread.call_count, 1)
        rows = app_module.ip_access.list_ips(self.uid)
        self.assertEqual(rows[0]["ip"], "198.51.100.10")
        self.assertFalse(rows[0]["allowed"])

    def test_localhost_recovers_after_other_ip_is_approved(self):
        self.login()
        self.client.get("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
        import ip_access
        with ip_access.connect() as db:
            db.execute("UPDATE allowed_ips SET allowed=0 WHERE ip='127.0.0.1'")
            db.execute("INSERT OR REPLACE INTO allowed_ips(user_id,ip,name,allowed) VALUES(?,?,?,1)",
                       (self.user_id, "192.0.2.15", "다른 기기"))
        self.assertEqual(self.client.get("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"}).status_code, 200)
        self.assertTrue(any(x["ip"] == "127.0.0.1" and x["allowed"]
                            for x in ip_access.list_ips(self.user_id)))

    def test_unapproved_user_sees_waiting_page_not_camera(self):
        self.login()
        with patch.object(app_module.threading, "Thread"):
            r = self.client.get("/", environ_overrides={"REMOTE_ADDR": "198.51.100.10"})
            self.assertEqual(r.status_code, 302)
            self.assertIn("/approval-pending", r.headers["Location"])
            r = self.client.get("/approval-pending", environ_overrides={"REMOTE_ADDR": "198.51.100.10"})
            self.assertEqual(r.status_code, 200)
            self.assertIn("승인 대기".encode(), r.data)
            self.assertEqual(self.client.get("/video_feed", environ_overrides={"REMOTE_ADDR": "198.51.100.10"}).status_code, 403)

    def test_approval_and_revocation(self):
        token = self.login()
        self.client.get("/")
        self.client.get("/", environ_overrides={"REMOTE_ADDR": "198.51.100.10"})
        self.assertEqual(self.client.post("/ip-management", data={"ip": "198.51.100.10", "name": "휴대폰",
            "allowed": "1"}, headers={"X-CSRF-Token": token}).status_code, 302)
        self.assertEqual(self.client.get("/", environ_overrides={"REMOTE_ADDR": "198.51.100.10"}).status_code, 200)
        self.assertEqual(self.client.post("/ip-management", data={"ip": "198.51.100.10", "name": "휴대폰",
            "allowed": "0", "csrf_token": token}).status_code, 302)
        self.assertEqual(self.client.get("/", environ_overrides={"REMOTE_ADDR": "198.51.100.10"}).status_code, 302)

    def test_csrf_and_ip_toggle_cannot_disable(self):
        token = self.login()
        self.assertEqual(self.client.post("/ip-management", data={}).status_code, 403)
        r = self.client.post("/toggle", json={"feature": "ip_monitoring"}, headers={"X-CSRF-Token": token})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.client.post("/logout").status_code, 403)
        self.assertEqual(self.client.post("/logout", data={"csrf_token": token}).status_code, 302)

    def test_registration_requires_invite(self):
        r = self.client.post("/register", data={"username": "another", "password": "strong-password-123",
            "invite_code": "wrong", "webhook": "https://discord.com/api/webhooks/123/token"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("초대 코드".encode(), r.data)

    def test_login_lockout(self):
        for _ in range(5):
            self.client.post("/login", data={"username": "member01", "password": "bad"})
        r = self.client.post("/login", data={"username": "member01", "password": "strong-password-123"})
        self.assertIn("시도 횟수 초과".encode(), r.data)

    def test_untrusted_proxy(self):
        with app_module.app.test_request_context("/", environ_base={"REMOTE_ADDR": "198.51.100.3"},
            headers={"X-Forwarded-For": "203.0.113.9"}):
            with patch.dict(os.environ, {"TRUSTED_PROXIES": ""}):
                self.assertEqual(app_module.get_client_ip(), "198.51.100.3")

if __name__ == "__main__":
    unittest.main()

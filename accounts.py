"""Local user accounts and encrypted Discord webhook preferences."""
import os
import sqlite3
import ipaddress
from urllib.parse import urlsplit
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.getenv("ABOUTCAM_USERS_DB", "users.db")

def _cipher():
    key = os.getenv("ABOUTCAM_FERNET_KEY")
    if not key:
        raise RuntimeError("ABOUTCAM_FERNET_KEY is required for account storage")
    return Fernet(key.encode("ascii"))

def validate_webhook(url):
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443):
            return False
        if host not in ("discord.com", "discordapp.com"):
            return False
        segments = parsed.path.strip("/").split("/")
        return len(segments) == 4 and segments[0:2] == ["api", "webhooks"] and segments[2].isdigit() and bool(segments[3]) and not parsed.query and not parsed.fragment
    except ValueError:
        return False

def _connect():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection

def init_db():
    _cipher()
    with _connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            webhook_ciphertext BLOB NOT NULL
        )""")
        columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
        if "is_admin" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        # Only seed the designated owner when no owner exists; never reclaim after transfer.
        db.execute("""UPDATE users SET is_admin=1 WHERE username=? COLLATE NOCASE
            AND NOT EXISTS (SELECT 1 FROM users WHERE is_admin=1)""", ("test123",))

def create_user(username, password, webhook):
    username = username.strip()
    if not (3 <= len(username) <= 32 and username.isascii() and all(c.isalnum() or c in "_-" for c in username)):
        raise ValueError("아이디는 영문·숫자·_·- 3~32자로 입력하세요.")
    if len(password) < 12 or len(password) > 128:
        raise ValueError("비밀번호는 12~128자로 입력하세요.")
    if not validate_webhook(webhook):
        raise ValueError("Discord 웹훅 URL 형식이 올바르지 않습니다.")
    encrypted = _cipher().encrypt(webhook.encode("utf-8"))
    with _connect() as db:
        try:
            cursor = db.execute("INSERT INTO users(username,password_hash,webhook_ciphertext) VALUES(?,?,?)",
                (username, generate_password_hash(password), encrypted))
            if username.lower() == "test123":
                db.execute("""UPDATE users SET is_admin=1 WHERE id=? AND
                    NOT EXISTS (SELECT 1 FROM users WHERE is_admin=1)""", (cursor.lastrowid,))
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            raise ValueError("이미 사용 중인 아이디입니다.") from None

def authenticate(username, password):
    with _connect() as db:
        user = db.execute("SELECT id,password_hash FROM users WHERE username = ?", (username.strip(),)).fetchone()
    if user and check_password_hash(user["password_hash"], password):
        return user["id"]
    return None

def user_webhook(user_id):
    with _connect() as db:
        user = db.execute("SELECT webhook_ciphertext FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return None
    try:
        return _cipher().decrypt(user["webhook_ciphertext"]).decode("utf-8")
    except InvalidToken:
        return None

def all_user_webhooks():
    with _connect() as db:
        ids = [row["id"] for row in db.execute("SELECT id FROM users")]
    return [url for user_id in ids if (url := user_webhook(user_id))]

def is_admin(user_id):
    with _connect() as db:
        row = db.execute("SELECT is_admin FROM users WHERE id=?", (user_id,)).fetchone()
        return bool(row and row["is_admin"])

def list_users():
    with _connect() as db:
        return [dict(row) for row in db.execute("SELECT id,username,is_admin FROM users ORDER BY username")]

def transfer_admin(current_id, password, target_username):
    """Atomically transfer sole ownership, requiring the current owner's password."""
    target_username = target_username.strip()
    with _connect() as db:
        db.execute("BEGIN IMMEDIATE")
        owner = db.execute("SELECT password_hash,is_admin FROM users WHERE id=?", (current_id,)).fetchone()
        if not owner or not owner["is_admin"]:
            raise ValueError("관리자 권한이 없습니다.")
        if not check_password_hash(owner["password_hash"], password):
            raise ValueError("현재 관리자 비밀번호가 올바르지 않습니다.")
        target = db.execute("SELECT id FROM users WHERE username=? COLLATE NOCASE", (target_username,)).fetchone()
        if not target or target["id"] == current_id:
            raise ValueError("양도받을 다른 기존 계정을 선택하세요.")
        db.execute("UPDATE users SET is_admin=0 WHERE is_admin=1")
        db.execute("UPDATE users SET is_admin=1 WHERE id=?", (target["id"],))
        return target["id"]

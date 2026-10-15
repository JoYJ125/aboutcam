"""Independent IP-management credentials. Recovery is controlled by a server-side secret."""
import hmac
import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import accounts

def _connect():
    return sqlite3.connect(accounts.DB_PATH, timeout=10)

def init_db():
    with _connect() as db:
        db.execute("CREATE TABLE IF NOT EXISTS ip_admin_credentials (id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL COLLATE NOCASE, password_hash TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1)")

def state():
    with _connect() as db:
        row = db.execute("SELECT username,version FROM ip_admin_credentials WHERE id=1").fetchone()
        return {'username':row[0], 'version':row[1]} if row else None

def verify(username,password):
    with _connect() as db:
        row = db.execute("SELECT username,password_hash FROM ip_admin_credentials WHERE id=1").fetchone()
    return bool(row and hmac.compare_digest(row[0].lower(),username.strip().lower()) and check_password_hash(row[1],password))

def _recovery_valid(code):
    expected=os.getenv('ABOUTCAM_ADMIN_RECOVERY_CODE','')
    return len(expected)>=24 and hmac.compare_digest(expected,code)

def provision(username,password,recovery):
    if not _recovery_valid(recovery):
        raise ValueError("서버 복구 코드가 올바르지 않습니다.")
    username=username.strip()
    if not (3<=len(username)<=32 and username.isascii() and all(c.isalnum() or c in '_-' for c in username)):
        raise ValueError("관리자 아이디는 영문·숫자·_·- 3~32자로 입력하세요.")
    if not (16<=len(password)<=128):
        raise ValueError("관리자 비밀번호는 16~128자로 설정하세요.")
    with _connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row=db.execute("SELECT version FROM ip_admin_credentials WHERE id=1").fetchone()
        db.execute("INSERT OR REPLACE INTO ip_admin_credentials(id,username,password_hash,version) VALUES(1,?,?,?)",
                   (username,generate_password_hash(password),row[0]+1 if row else 1))

def change(old_username,old_password,new_username,new_password):
    if not verify(old_username,old_password):
        raise ValueError("기존 관리자 인증 정보가 올바르지 않습니다.")
    username=new_username.strip()
    if not (3<=len(username)<=32 and username.isascii() and all(c.isalnum() or c in '_-' for c in username)):
        raise ValueError("관리자 아이디 형식이 올바르지 않습니다.")
    if not 16<=len(new_password)<=128:
        raise ValueError("새 비밀번호는 16~128자로 입력하세요.")
    with _connect() as db:
        db.execute("UPDATE ip_admin_credentials SET username=?,password_hash=?,version=version+1 WHERE id=1",
                   (username,generate_password_hash(new_password)))

def delete(username,password,recovery):
    if not verify(username,password) or not _recovery_valid(recovery):
        raise ValueError("관리자 인증 정보 또는 서버 복구 코드가 올바르지 않습니다.")
    with _connect() as db:
        db.execute("DELETE FROM ip_admin_credentials WHERE id=1")

"""Per-account IP allowlist. Loopback is the only automatic bootstrap address."""
import argparse
import ipaddress
import sqlite3
import time
from accounts import DB_PATH

def normalize(ip):
    return str(ipaddress.ip_address(ip))

def connect():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS allowed_ips (
            user_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            allowed INTEGER NOT NULL DEFAULT 0,
            last_seen INTEGER,
            last_alert INTEGER,
            PRIMARY KEY(user_id, ip),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")

def bootstrap(user_id, ip):
    """Always restore authenticated loopback access on the server PC.

    Loopback traffic never traverses the LAN; only authenticated users on the
    server itself benefit. This prevents an accidental local admin lockout.
    """
    ip = normalize(ip)
    if not ipaddress.ip_address(ip).is_loopback:
        return False
    with connect() as db:
        db.execute("""INSERT INTO allowed_ips(user_id,ip,name,allowed)
            VALUES(?,?,?,1)
            ON CONFLICT(user_id,ip) DO UPDATE SET allowed=1""",
            (user_id, ip, "메인 컴퓨터 (로컬)"))
    return True

def check(user_id, ip):
    ip = normalize(ip)
    now = int(time.time())
    with connect() as db:
        row = db.execute("SELECT allowed,last_alert FROM allowed_ips WHERE user_id=? AND ip=?", (user_id, ip)).fetchone()
        if row is None:
            db.execute("INSERT INTO allowed_ips(user_id,ip,name,allowed,last_seen,last_alert) VALUES(?,?,?,0,?,?)",
                       (user_id, ip, "", now, now))
            return False, True
        db.execute("UPDATE allowed_ips SET last_seen=? WHERE user_id=? AND ip=?", (now, user_id, ip))
        if row["allowed"]:
            return True, False
        alert = row["last_alert"] is None or now - row["last_alert"] >= 300
        if alert:
            db.execute("UPDATE allowed_ips SET last_alert=? WHERE user_id=? AND ip=?", (now, user_id, ip))
        return False, alert

def list_ips(user_id):
    with connect() as db:
        return [dict(row) for row in db.execute(
            "SELECT ip,name,allowed,last_seen FROM allowed_ips WHERE user_id=? ORDER BY allowed DESC,ip", (user_id,))]

def change(user_id, ip, name, allowed, current_ip):
    ip = normalize(ip)
    name = name.strip()
    if not name or len(name) > 60:
        raise ValueError("IP 이름은 1~60자로 입력하세요.")
    with connect() as db:
        row = db.execute("SELECT allowed FROM allowed_ips WHERE user_id=? AND ip=?", (user_id, ip)).fetchone()
        if row is None:
            raise ValueError("등록된 IP가 아닙니다.")
        if ip == normalize(current_ip) and not allowed:
            raise ValueError("현재 접속 중인 IP는 차단할 수 없습니다.")
        if row["allowed"] and not allowed:
            count = db.execute("SELECT COUNT(*) FROM allowed_ips WHERE user_id=? AND allowed=1", (user_id,)).fetchone()[0]
            if count <= 1:
                raise ValueError("마지막 허가 IP는 차단할 수 없습니다.")
        db.execute("UPDATE allowed_ips SET name=?,allowed=? WHERE user_id=? AND ip=?",
                   (name, int(bool(allowed)), user_id, ip))

def cli():
    parser = argparse.ArgumentParser(description="AboutCam IP 복구/사전 허가 도구")
    parser.add_argument("command", choices=["allow", "list"])
    parser.add_argument("username")
    parser.add_argument("ip", nargs="?")
    parser.add_argument("name", nargs="?", default="관리자 승인")
    args = parser.parse_args()
    init_db()
    with connect() as db:
        user = db.execute("SELECT id FROM users WHERE username=? COLLATE NOCASE", (args.username,)).fetchone()
        if not user:
            parser.error("해당 사용자가 없습니다.")
        uid = user["id"]
        if args.command == "list":
            for item in list_ips(uid):
                print(item)
            return
        if not args.ip:
            parser.error("allow 명령에는 IP 주소가 필요합니다.")
        ip = normalize(args.ip)
        if not args.name.strip() or len(args.name) > 60:
            parser.error("이름은 1~60자여야 합니다.")
        db.execute("""INSERT INTO allowed_ips(user_id,ip,name,allowed) VALUES(?,?,?,1)
            ON CONFLICT(user_id,ip) DO UPDATE SET name=excluded.name,allowed=1""",
            (uid, ip, args.name.strip()))
    print(f"허가 완료: {args.username} / {ip}")

if __name__ == "__main__":
    cli()

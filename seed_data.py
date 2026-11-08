"""
Database seeder script to populate realistic users, login audit logs,
brute force attack simulations, and security alerts for immediate demonstration.
"""

import os
import random
import datetime
from config import Config
from database import (
    init_db,
    get_db,
    create_user,
    record_login_attempt,
    log_security_alert,
    update_user_lock_state
)
from security.auth import hash_password
from security.analyzer import analyze_password

def seed_database():
    # Remove existing db file if present to seed freshly
    if os.path.exists(Config.DATABASE_PATH):
        try:
            os.remove(Config.DATABASE_PATH)
        except Exception:
            pass

    init_db()
    print("Database schema initialized.")

    users_to_seed = [
        {
            "username": "admin",
            "email": "admin@cyberdefense.org",
            "password": "AdminSecOps#2026!🛡️",
            "role": "admin"
        },
        {
            "username": "alice_sec",
            "email": "alice@cyberdefense.org",
            "password": "Al!ceCyber#9921$Pro",
            "role": "user"
        },
        {
            "username": "marcus_dev",
            "email": "marcus@company.internal",
            "password": "M@rcusSecureDev2025*",
            "role": "user"
        },
        {
            "username": "sarah_analyst",
            "email": "sarah@soc.defense",
            "password": "S@rahEntropy!888#",
            "role": "user"
        },
        {
            "username": "bob_weak",
            "email": "bob@personal.net",
            "password": "password1234",
            "role": "user"
        }
    ]

    for u in users_to_seed:
        analysis = analyze_password(u['password'])
        hashed = hash_password(u['password'])
        user_id = create_user(
            username=u['username'],
            email=u['email'],
            password_hash=hashed,
            role=u['role'],
            score=analysis['score'],
            entropy=analysis['effective_entropy']
        )
        print(f"Created user: {u['username']} (Role: {u['role']}, Score: {analysis['score']})")

    # Set bob_weak as locked out to demonstrate lockout state
    bob_user_id = 5
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    lock_expiry = (now_utc + datetime.timedelta(minutes=12)).strftime("%Y-%m-%d %H:%M:%S")
    update_user_lock_state(bob_user_id, is_locked=True, locked_until=lock_expiry, failed_attempts=5)

    # Seed login attempts & audit logs
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
        "Python-urllib/3.10 (Automated Attacker Tool)",
        "Hydra/9.5 (Network Logon Cracker)"
    ]

    legit_ips = ["192.168.1.105", "10.0.4.22", "172.16.0.45", "127.0.0.1"]
    attacker_ips = ["185.220.101.5", "45.154.255.89", "194.26.29.112"]

    # Generate historical records over past 5 days
    for day_offset in range(5, 0, -1):
        day_time = now_utc - datetime.timedelta(days=day_offset)
        
        # Successful logins
        for _ in range(random.randint(6, 12)):
            user = random.choice(["admin", "alice_sec", "marcus_dev", "sarah_analyst"])
            t = day_time + datetime.timedelta(hours=random.randint(1, 22), minutes=random.randint(0, 59))
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO login_attempts (username, ip_address, user_agent, status, failure_reason, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user, random.choice(legit_ips), user_agents[0], "SUCCESS", None, t.strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            conn.close()

        # Some sporadic failed logins
        for _ in range(random.randint(2, 6)):
            t = day_time + datetime.timedelta(hours=random.randint(1, 23), minutes=random.randint(0, 59))
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO login_attempts (username, ip_address, user_agent, status, failure_reason, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (random.choice(["admin", "alice_sec", "unknown_user", "root"]), random.choice(attacker_ips), user_agents[3], "FAILED", "Invalid credentials", t.strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            conn.close()

    # Simulate recent brute-force attack today on 'admin' and 'bob_weak'
    today_base = now_utc - datetime.timedelta(minutes=45)
    for i in range(7):
        t = today_base + datetime.timedelta(minutes=i*2)
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO login_attempts (username, ip_address, user_agent, status, failure_reason, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("admin", "185.220.101.5", user_agents[4], "FAILED", "Invalid credentials (Brute-force dictionary)", t.strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()

    # Failed attempts for bob_weak leading to lockout
    for i in range(5):
        t = now_utc - datetime.timedelta(minutes=15 - i)
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO login_attempts (username, ip_address, user_agent, status, failure_reason, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("bob_weak", "194.26.29.112", user_agents[3], "FAILED", "Incorrect password", t.strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()

    # Blocked attempt for bob_weak while locked
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO login_attempts (username, ip_address, user_agent, status, failure_reason, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, ("bob_weak", "194.26.29.112", user_agents[3], "BLOCKED_LOCKED", "Account locked (expires in 12m)", now_utc.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

    # Seed Security Alerts
    log_security_alert(
        alert_type="BRUTE_FORCE_DETECTED",
        description="High frequency dictionary attack detected targeting account 'admin' from IP 185.220.101.5.",
        severity="CRITICAL",
        ip_address="185.220.101.5",
        username="admin"
    )
    log_security_alert(
        alert_type="ACCOUNT_LOCKED",
        description="Account 'bob_weak' was automatically locked after 5 consecutive failed attempts from IP 194.26.29.112.",
        severity="HIGH",
        ip_address="194.26.29.112",
        username="bob_weak"
    )
    log_security_alert(
        alert_type="WEAK_PASSWORD_REGISTERED",
        description="User 'bob_weak' registered with weak dictionary password 'password1234' (Score: 12/100).",
        severity="MEDIUM",
        username="bob_weak"
    )
    log_security_alert(
        alert_type="SUSPICIOUS_IP",
        description="IP 185.220.101.5 flagged for automated scanner signature (Hydra User-Agent).",
        severity="HIGH",
        ip_address="185.220.101.5",
        username="root"
    )

    print("Seed data successfully populated!")

if __name__ == "__main__":
    seed_database()

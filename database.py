"""
Database access and query utilities using SQLite.
Includes parameterized queries, schema creation, audit logging,
and security analytics aggregations.
"""

import sqlite3
import datetime
from typing import Optional, List, Dict, Any
from config import Config

def get_db():
    """Returns a SQLite database connection with row dictionary mapping."""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """Initializes tables, indices, and default schema."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        password_score INTEGER DEFAULT 0,
        password_entropy REAL DEFAULT 0.0,
        created_at TEXT DEFAULT (datetime('now')),
        last_login_at TEXT,
        last_login_ip TEXT,
        failed_attempts INTEGER DEFAULT 0,
        is_locked INTEGER DEFAULT 0,
        locked_until TEXT
    )
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        user_agent TEXT,
        status TEXT NOT NULL,
        failure_reason TEXT,
        timestamp TEXT DEFAULT (datetime('now'))
    )
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL,
        ip_address TEXT,
        username TEXT,
        timestamp TEXT DEFAULT (datetime('now')),
        is_resolved INTEGER DEFAULT 0
    )
    """)
    
    # Indexes for fast querying & security monitoring
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attempts_username ON login_attempts(username)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attempts_ip ON login_attempts(ip_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attempts_timestamp ON login_attempts(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp)")
    
    conn.commit()
    conn.close()

# ----------------- User Management -----------------

def create_user(username: str, email: str, password_hash: str, role: str = 'user', score: int = 0, entropy: float = 0.0) -> Optional[int]:
    """Creates a new user record."""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, role, password_score, password_entropy)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username.strip().lower(), email.strip().lower(), password_hash, role, score, entropy))
        conn.commit()
        user_id = cursor.lastrowid
        return user_id
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def get_user_by_username(username: str) -> Optional[dict]:
    """Retrieves user by username (case-insensitive)."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username.strip().lower(),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_by_id(user_id: int) -> Optional[dict]:
    """Retrieves user by numeric ID."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def update_user_password(user_id: int, password_hash: str, score: int, entropy: float) -> bool:
    """Updates user password hash and new security score."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users
        SET password_hash = ?, password_score = ?, password_entropy = ?
        WHERE id = ?
    """, (password_hash, score, entropy, user_id))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def update_user_lock_state(user_id: int, is_locked: bool, locked_until: Optional[str] = None, failed_attempts: Optional[int] = None):
    """Sets account lock state and optional expiration timestamp."""
    conn = get_db()
    cursor = conn.cursor()
    if failed_attempts is not None:
        cursor.execute("""
            UPDATE users
            SET is_locked = ?, locked_until = ?, failed_attempts = ?
            WHERE id = ?
        """, (1 if is_locked else 0, locked_until, failed_attempts, user_id))
    else:
        cursor.execute("""
            UPDATE users
            SET is_locked = ?, locked_until = ?
            WHERE id = ?
        """, (1 if is_locked else 0, locked_until, user_id))
    conn.commit()
    conn.close()

def update_login_success(user_id: int, ip_address: str):
    """Updates last login timestamp and resets failed attempts upon successful login."""
    conn = get_db()
    cursor = conn.cursor()
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        UPDATE users
        SET last_login_at = ?, last_login_ip = ?, failed_attempts = 0, is_locked = 0, locked_until = NULL
        WHERE id = ?
    """, (now_str, ip_address, user_id))
    conn.commit()
    conn.close()

def increment_failed_attempts(user_id: int) -> int:
    """Increments user's failed attempts count and returns new count."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?", (user_id,))
    cursor.execute("SELECT failed_attempts FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    new_count = row['failed_attempts'] if row else 1
    conn.commit()
    conn.close()
    return new_count

def get_all_users() -> List[dict]:
    """Retrieves all users for admin review."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, password_score, password_entropy, created_at, last_login_at, is_locked, locked_until, failed_attempts FROM users ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ----------------- Login Attempts & Audit Logs -----------------

def record_login_attempt(username: str, ip_address: str, user_agent: str, status: str, failure_reason: Optional[str] = None):
    """Logs an authentication attempt (SUCCESS, FAILED, or BLOCKED_LOCKED)."""
    conn = get_db()
    cursor = conn.cursor()
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO login_attempts (username, ip_address, user_agent, status, failure_reason, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (username.strip().lower(), ip_address, user_agent[:255] if user_agent else "Unknown", status, failure_reason, now_str))
    conn.commit()
    conn.close()

def get_recent_failed_attempts_count(username: str, minutes: int = 15) -> int:
    """Counts failed attempts for a username within recent time window."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) as cnt FROM login_attempts
        WHERE username = ? AND status != 'SUCCESS'
        AND datetime(timestamp) >= datetime('now', ?)
    """, (username.strip().lower(), f"-{minutes} minutes"))
    row = cursor.fetchone()
    conn.close()
    return row['cnt'] if row else 0

def get_recent_failed_attempts_by_ip(ip_address: str, minutes: int = 15) -> int:
    """Counts failed attempts from an IP within recent time window."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) as cnt FROM login_attempts
        WHERE ip_address = ? AND status != 'SUCCESS'
        AND datetime(timestamp) >= datetime('now', ?)
    """, (ip_address, f"-{minutes} minutes"))
    row = cursor.fetchone()
    conn.close()
    return row['cnt'] if row else 0

def get_user_login_history(username: str, limit: int = 20) -> List[dict]:
    """Retrieves login history for a specific user."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, ip_address, user_agent, status, failure_reason, timestamp
        FROM login_attempts
        WHERE username = ?
        ORDER BY id DESC LIMIT ?
    """, (username.strip().lower(), limit))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_audit_logs(limit: int = 100, status_filter: Optional[str] = None, search: Optional[str] = None) -> List[dict]:
    """Retrieves system-wide audit logs with optional filtering."""
    conn = get_db()
    cursor = conn.cursor()
    
    query = "SELECT * FROM login_attempts WHERE 1=1"
    params = []
    
    if status_filter:
        query += " AND status = ?"
        params.append(status_filter)
        
    if search:
        query += " AND (username LIKE ? OR ip_address LIKE ? OR failure_reason LIKE ?)"
        search_param = f"%{search}%"
        params.extend([search_param, search_param, search_param])
        
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ----------------- Security Alerts -----------------

def log_security_alert(alert_type: str, description: str, severity: str, ip_address: Optional[str] = None, username: Optional[str] = None):
    """Inserts a security alert record for dashboard monitoring."""
    conn = get_db()
    cursor = conn.cursor()
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO security_alerts (alert_type, description, severity, ip_address, username, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (alert_type, description, severity, ip_address, username, now_str))
    conn.commit()
    conn.close()

def get_security_alerts(limit: int = 50, unresolved_only: bool = False) -> List[dict]:
    """Retrieves recent security alerts."""
    conn = get_db()
    cursor = conn.cursor()
    query = "SELECT * FROM security_alerts WHERE 1=1"
    if unresolved_only:
        query += " AND is_resolved = 0"
    query += " ORDER BY id DESC LIMIT ?"
    cursor.execute(query, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ----------------- Metrics & Aggregations -----------------

def get_aggregate_security_metrics() -> Dict[str, Any]:
    """Computes comprehensive security metrics for dashboard visualization."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Total Users
    cursor.execute("SELECT COUNT(*) as cnt FROM users")
    total_users = cursor.fetchone()['cnt']
    
    # Locked Accounts
    cursor.execute("SELECT COUNT(*) as cnt FROM users WHERE is_locked = 1")
    locked_users = cursor.fetchone()['cnt']
    
    # Total Attempts
    cursor.execute("SELECT COUNT(*) as cnt FROM login_attempts")
    total_attempts = cursor.fetchone()['cnt']
    
    # Successful vs Failed
    cursor.execute("SELECT status, COUNT(*) as cnt FROM login_attempts GROUP BY status")
    status_counts = {r['status']: r['cnt'] for r in cursor.fetchall()}
    success_count = status_counts.get('SUCCESS', 0)
    failed_count = status_counts.get('FAILED', 0)
    blocked_count = status_counts.get('BLOCKED_LOCKED', 0)
    
    # Brute Force Alerts count
    cursor.execute("SELECT COUNT(*) as cnt FROM security_alerts WHERE alert_type = 'BRUTE_FORCE_DETECTED'")
    brute_force_alerts = cursor.fetchone()['cnt']
    
    # Recent attempts grouped by date (last 7 days)
    cursor.execute("""
        SELECT substr(timestamp, 1, 10) as day,
               SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) as success,
               SUM(CASE WHEN status != 'SUCCESS' THEN 1 ELSE 0 END) as failed
        FROM login_attempts
        WHERE timestamp >= datetime('now', '-7 days')
        GROUP BY day
        ORDER BY day ASC
    """)
    daily_stats = [dict(r) for r in cursor.fetchall()]
    
    # Password strength distribution among users
    cursor.execute("""
        SELECT 
            CASE 
                WHEN password_score >= 85 THEN 'Very Strong'
                WHEN password_score >= 70 THEN 'Strong'
                WHEN password_score >= 50 THEN 'Moderate'
                WHEN password_score >= 25 THEN 'Weak'
                ELSE 'Very Weak'
            END as strength_tier,
            COUNT(*) as count
        FROM users
        GROUP BY strength_tier
    """)
    strength_dist = {r['strength_tier']: r['count'] for r in cursor.fetchall()}
    
    # Most targeted usernames in failed attacks
    cursor.execute("""
        SELECT username, COUNT(*) as failed_attempts
        FROM login_attempts
        WHERE status != 'SUCCESS'
        GROUP BY username
        ORDER BY failed_attempts DESC
        LIMIT 5
    """)
    targeted_accounts = [dict(r) for r in cursor.fetchall()]
    
    # Top suspicious attacker IPs
    cursor.execute("""
        SELECT ip_address, COUNT(*) as total_failures
        FROM login_attempts
        WHERE status != 'SUCCESS'
        GROUP BY ip_address
        ORDER BY total_failures DESC
        LIMIT 5
    """)
    top_suspicious_ips = [dict(r) for r in cursor.fetchall()]
    
    conn.close()
    
    return {
        "total_users": total_users,
        "locked_users": locked_users,
        "total_attempts": total_attempts,
        "success_count": success_count,
        "failed_count": failed_count,
        "blocked_count": blocked_count,
        "brute_force_alerts": brute_force_alerts,
        "daily_stats": daily_stats,
        "strength_dist": strength_dist,
        "targeted_accounts": targeted_accounts,
        "top_suspicious_ips": top_suspicious_ips
    }

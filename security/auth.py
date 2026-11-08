"""
Authentication and Brute-Force Defense Module.
Provides secure password hashing/salting with bcrypt, login attempt tracking,
progressive lockout mechanisms, and brute-force mitigation.
"""

import bcrypt
import datetime
import re
from typing import Tuple, Optional, Dict, Any
from config import Config
from database import (
    get_user_by_username,
    get_user_by_id,
    create_user,
    update_user_password,
    update_user_lock_state,
    update_login_success,
    increment_failed_attempts,
    record_login_attempt,
    get_recent_failed_attempts_count,
    get_recent_failed_attempts_by_ip,
    log_security_alert
)
from .analyzer import analyze_password

def hash_password(plain_password: str) -> str:
    """Hashes a password with a random unique salt using bcrypt."""
    salt = bcrypt.gensalt(rounds=Config.BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against the stored bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

def authenticate_user(username: str, password: str, ip_address: str, user_agent: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """
    Authenticates a user with:
    - Attempt tracking per username and IP
    - Account lockout enforcement
    - Brute-force detection and alerting
    - Bcrypt verification
    """
    clean_username = username.strip().lower()
    
    # 1. Check IP-based brute force threshold
    recent_ip_failures = get_recent_failed_attempts_by_ip(ip_address, minutes=Config.ATTEMPT_WINDOW_MINUTES)
    if recent_ip_failures >= 15:
        record_login_attempt(clean_username, ip_address, user_agent, "BLOCKED_LOCKED", "IP temporarily throttled due to excessive failed attempts")
        log_security_alert(
            alert_type="SUSPICIOUS_IP",
            description=f"IP address {ip_address} has exceeded threshold with {recent_ip_failures} failed attempts.",
            severity="CRITICAL",
            ip_address=ip_address,
            username=clean_username
        )
        return False, None, "Your IP address is temporarily blocked due to suspicious activity. Please try again later."

    # 2. Query user from database
    user = get_user_by_username(clean_username)
    if not user:
        record_login_attempt(clean_username, ip_address, user_agent, "FAILED", "Invalid username or password")
        return False, None, "Invalid username or password."

    user_id = user['id']

    # 3. Check Account Lockout State
    if user['is_locked']:
        locked_until_str = user['locked_until']
        if locked_until_str:
            try:
                locked_until = datetime.datetime.fromisoformat(locked_until_str)
            except ValueError:
                locked_until = datetime.datetime.strptime(locked_until_str, "%Y-%m-%d %H:%M:%S")
                
            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            
            # If still locked
            if now < locked_until:
                remaining_sec = int((locked_until - now).total_seconds())
                remaining_min = (remaining_sec // 60) + 1
                record_login_attempt(clean_username, ip_address, user_agent, "BLOCKED_LOCKED", f"Account locked (expires in {remaining_sec}s)")
                return False, None, f"Account is temporarily locked due to repeated failed logins. Please try again in ~{remaining_min} minute{'s' if remaining_min > 1 else ''}."
            else:
                # Lockout time has expired, unlock account
                update_user_lock_state(user_id, is_locked=False, locked_until=None, failed_attempts=0)
                user['is_locked'] = 0
                user['failed_attempts'] = 0

    # 4. Password Verification via bcrypt
    is_valid = verify_password(password, user['password_hash'])

    if is_valid:
        # Successful authentication: reset failed count and log
        update_login_success(user_id, ip_address)
        record_login_attempt(clean_username, ip_address, user_agent, "SUCCESS")
        return True, user, "Authentication successful."
    else:
        # Authentication failed
        new_failed_count = increment_failed_attempts(user_id)
        record_login_attempt(clean_username, ip_address, user_agent, "FAILED", "Invalid credentials")
        
        # Check if lockout threshold reached
        if new_failed_count >= Config.MAX_FAILED_ATTEMPTS:
            lockout_expiry = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) + datetime.timedelta(minutes=Config.LOCKOUT_DURATION_MINUTES)
            lockout_str = lockout_expiry.strftime("%Y-%m-%d %H:%M:%S")
            update_user_lock_state(user_id, is_locked=True, locked_until=lockout_str)
            
            # Log security alerts
            log_security_alert(
                alert_type="ACCOUNT_LOCKED",
                description=f"Account '{clean_username}' was locked after {new_failed_count} consecutive failed attempts from IP {ip_address}.",
                severity="HIGH",
                ip_address=ip_address,
                username=clean_username
            )
            log_security_alert(
                alert_type="BRUTE_FORCE_DETECTED",
                description=f"Brute-force attack detected on account '{clean_username}' from IP {ip_address}.",
                severity="HIGH",
                ip_address=ip_address,
                username=clean_username
            )
            
            return False, None, f"Account locked! Exceeded maximum failed login attempts ({Config.MAX_FAILED_ATTEMPTS}). Your account is locked for {Config.LOCKOUT_DURATION_MINUTES} minutes."
        else:
            remaining = Config.MAX_FAILED_ATTEMPTS - new_failed_count
            return False, None, f"Invalid username or password. Warning: {remaining} attempt{'s' if remaining > 1 else ''} remaining before temporary account lockout."

def register_user_account(username: str, email: str, password: str, role: str = 'user') -> Tuple[bool, str, Optional[int]]:
    """
    Validates input parameters, assesses password strength, hashes password,
    and creates new user in SQLite database.
    """
    clean_username = username.strip().lower()
    clean_email = email.strip().lower()

    # Username format validation
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', clean_username):
        return False, "Username must be 3-20 characters long and contain only letters, numbers, and underscores.", None

    # Email format validation
    if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', clean_email):
        return False, "Please enter a valid email address.", None

    # Password length validation
    if len(password) < Config.MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {Config.MIN_PASSWORD_LENGTH} characters long.", None

    # Check if username or email already registered
    existing_user = get_user_by_username(clean_username)
    if existing_user:
        return False, f"Username '{clean_username}' is already taken. Please choose another.", None

    # Analyze password strength
    analysis = analyze_password(password)
    if analysis['dictionary_analysis']['is_exact_match']:
        return False, "This password is on the list of known compromised/common passwords. Please select a stronger, unique password.", None

    # Hash with bcrypt
    hashed = hash_password(password)

    # Insert user into database
    user_id = create_user(
        username=clean_username,
        email=clean_email,
        password_hash=hashed,
        role=role,
        score=analysis['score'],
        entropy=analysis['effective_entropy']
    )

    if not user_id:
        return False, "Registration failed due to a database conflict or error. Try again.", None

    if analysis['score'] < 30:
        log_security_alert(
            alert_type="WEAK_PASSWORD_REGISTERED",
            description=f"User '{clean_username}' registered with a weak password (Score: {analysis['score']}/100, Entropy: {analysis['effective_entropy']} bits).",
            severity="MEDIUM",
            username=clean_username
        )

    return True, "Account registered successfully!", user_id

def update_password(user_id: int, current_password: str, new_password: str) -> Tuple[bool, str]:
    """Validates old password, evaluates new password, and updates hash."""
    user = get_user_by_id(user_id)
    if not user:
        return False, "User not found."

    if not verify_password(current_password, user['password_hash']):
        return False, "Current password is incorrect."

    if len(new_password) < Config.MIN_PASSWORD_LENGTH:
        return False, f"New password must be at least {Config.MIN_PASSWORD_LENGTH} characters long."

    analysis = analyze_password(new_password)
    if analysis['dictionary_analysis']['is_exact_match']:
        return False, "New password is a known weak dictionary password. Please pick a secure password."

    new_hash = hash_password(new_password)
    success = update_user_password(user_id, new_hash, analysis['score'], analysis['effective_entropy'])
    
    if success:
        return True, "Password updated successfully!"
    return False, "Failed to update password. Please try again."

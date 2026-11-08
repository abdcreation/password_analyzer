import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cyber-defense-sec-key-9a8b7c6d5e4f3a2b1c0d')
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'auth_system.db')
    
    # Security Policies
    BCRYPT_ROUNDS = 12
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15
    ATTEMPT_WINDOW_MINUTES = 15
    MIN_PASSWORD_LENGTH = 8
    
    # Session Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour in seconds

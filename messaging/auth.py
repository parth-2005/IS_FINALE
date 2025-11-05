# messaging/auth.py
import json
import os
import hashlib

USER_FILE = "users.json"

def _hash_password(password: str) -> str:
    """Hash password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def _load_users():
    """Load user data from file or initialize empty dict."""
    if not os.path.exists(USER_FILE):
        return {}
    with open(USER_FILE, "r") as f:
        return json.load(f)

def _save_users(users):
    """Save user data to file."""
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=4)

def register_user(username: str, password: str) -> bool:
    """Register a new user (returns False if user already exists)."""
    users = _load_users()
    if username in users:
        return False
    users[username] = _hash_password(password)
    _save_users(users)
    return True

def authenticate(username: str, password: str) -> bool:
    """Check credentials (username + hashed password)."""
    users = _load_users()
    return users.get(username) == _hash_password(password)

def list_users():
    """Return a list of all registered usernames."""
    return list(_load_users().keys())

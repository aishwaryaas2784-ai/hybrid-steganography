"""
users.py
User account registration and login with securely hashed passwords.
"""

import os
import json
import hashlib
import secrets

USERS_FILE = "users.json"


def _load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def _save_users(users: dict):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()


def register_user(username: str, password: str, full_name: str, email: str, phone: str = "") -> tuple:
    username = username.strip().lower()
    email = email.strip().lower()

    if not username or not password or not full_name or not email:
        return False, "Username, password, full name, and email are all required."

    if len(password) < 6:
        return False, "Password must be at least 6 characters long."

    users = _load_users()

    if username in users:
        return False, f"Username '{username}' is already taken. Please choose another."

    for existing_username, data in users.items():
        if data.get("email") == email:
            return False, f"An account with email '{email}' already exists."

    salt = secrets.token_hex(16)
    password_hash = _hash_password(password, salt)

    users[username] = {
        "full_name": full_name.strip(),
        "email": email,
        "phone": phone.strip(),
        "salt": salt,
        "password_hash": password_hash
    }
    _save_users(users)
    return True, "Account created successfully."


def verify_login(username: str, password: str) -> tuple:
    username = username.strip().lower()
    users = _load_users()

    if username not in users:
        return False, "No account found with that username."

    user = users[username]
    computed_hash = _hash_password(password, user["salt"])

    if computed_hash != user["password_hash"]:
        return False, "Incorrect password."

    return True, "Login successful."


def get_user_info(username: str) -> dict:
    username = username.strip().lower()
    users = _load_users()
    return users.get(username, {})


def user_exists(username: str) -> bool:
    username = username.strip().lower()
    return username in _load_users()
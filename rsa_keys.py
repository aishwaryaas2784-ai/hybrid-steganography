"""
rsa_keys.py
Per-user RSA-2048 keypair generation and management.
"""

import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

KEY_DIR = "keys"


def _user_key_dir(username: str) -> str:
    return os.path.join(KEY_DIR, username)


def generate_user_keypair(username: str):
    user_dir = _user_key_dir(username)
    private_path = os.path.join(user_dir, "private.pem")
    public_path = os.path.join(user_dir, "public.pem")

    if os.path.exists(private_path) and os.path.exists(public_path):
        return

    os.makedirs(user_dir, exist_ok=True)
    key = RSA.generate(2048)

    with open(private_path, "wb") as f:
        f.write(key.export_key())

    with open(public_path, "wb") as f:
        f.write(key.publickey().export_key())


def get_public_key(username: str) -> RSA.RsaKey:
    public_path = os.path.join(_user_key_dir(username), "public.pem")
    if not os.path.exists(public_path):
        raise ValueError(f"No public key found for user '{username}'.")
    with open(public_path, "rb") as f:
        return RSA.import_key(f.read())


def get_private_key(username: str) -> RSA.RsaKey:
    private_path = os.path.join(_user_key_dir(username), "private.pem")
    if not os.path.exists(private_path):
        raise ValueError(f"No private key found for user '{username}'.")
    with open(private_path, "rb") as f:
        return RSA.import_key(f.read())


def encrypt_session_key(session_password: str, recipient_username: str) -> str:
    public_key = get_public_key(recipient_username)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(session_password.encode("utf-8"))
    return base64.b64encode(encrypted).decode("utf-8")


def decrypt_session_key(encrypted_b64: str, username: str) -> str:
    private_key = get_private_key(username)
    cipher = PKCS1_OAEP.new(private_key)
    encrypted = base64.b64decode(encrypted_b64)
    decrypted = cipher.decrypt(encrypted)
    return decrypted.decode("utf-8")
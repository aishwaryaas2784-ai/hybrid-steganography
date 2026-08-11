"""
encrypt.py
AES-256 encryption/decryption with SHA-256 integrity verification.
Detects if the message was tampered with or corrupted during transmission.
"""

import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

SALT = b"stego_project_salt_2026"


def derive_key(password: str) -> bytes:
    return PBKDF2(password, SALT, dkLen=32, count=100000)


def encrypt(message: str, password: str = "default_key123") -> str:
    """
    Encrypts message with AES-256, after prepending a SHA-256 hash of the
    original plaintext for tamper/corruption detection on decrypt.
    """
    key = derive_key(password)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    msg_hash = hashlib.sha256(message.encode("utf-8")).hexdigest()
    combined = msg_hash + "||" + message  # hash || original message

    ciphertext = cipher.encrypt(pad(combined.encode("utf-8"), AES.block_size))
    encrypted_data = iv + ciphertext
    return base64.b64encode(encrypted_data).decode("utf-8")


def decrypt(encrypted_message: str, password: str = "default_key123") -> str:
    """
    Decrypts and verifies integrity via SHA-256. Raises ValueError if the
    message was tampered with or corrupted (hash mismatch).
    """
    key = derive_key(password)
    encrypted_data = base64.b64decode(encrypted_message)

    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted_bytes = unpad(decrypted_padded, AES.block_size)
    combined = decrypted_bytes.decode("utf-8")

    msg_hash, message = combined.split("||", 1)
    computed_hash = hashlib.sha256(message.encode("utf-8")).hexdigest()

    if computed_hash != msg_hash:
        raise ValueError("Integrity check failed: message may have been tampered with or corrupted in transit.")

    return message


if __name__ == "__main__":
    secret = "This is a confidential message for the hybrid steganography system."
    password = "MySecureKey2026"

    print("Original message:", secret)

    enc = encrypt(secret, password)
    print("\nEncrypted (base64):", enc)

    dec = decrypt(enc, password)
    print("\nDecrypted message:", dec)

    assert dec == secret, "Mismatch!"
    print("\n✅ Encryption/Decryption + SHA-256 integrity check passed successfully.")

    # Simulate tampering to prove the integrity check actually works
    tampered = enc[:-4] + "abcd"
    try:
        decrypt(tampered, password)
        print("⚠️ WARNING: Tampering was NOT detected — check the code.")
    except Exception as e:
        print(f"✅ Tampering correctly detected: {e}")
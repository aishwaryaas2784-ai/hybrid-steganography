
import os
import base64
import hashlib
import hmac
import struct

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Legacy encryption settings — preserve old messages
LEGACY_SALT = b"stego_project_salt_2026"
LEGACY_ITERATIONS = 100000

# New encryption settings
MAGIC = b"HYBENC02"
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 1024 * 1024


def _legacy_key(password):
    return PBKDF2(
        password.encode("utf-8"),
        LEGACY_SALT,
        dkLen=32,
        count=LEGACY_ITERATIONS
    )


# --------------------------------------------------
# LEGACY STRING ENCRYPTION
# --------------------------------------------------

def encrypt(message: str, password: str) -> str:
    """Encrypt text using the existing AES-CBC format."""
    key = _legacy_key(password)
    iv = get_random_bytes(16)

    raw = message.encode("utf-8")
    digest = hashlib.sha256(raw).digest()
    padded = pad(digest + raw, AES.block_size)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded)

    return base64.b64encode(iv + encrypted).decode("utf-8")


def decrypt(encrypted_message: str, password: str) -> str:
    """Decrypt existing AES-CBC messages."""
    try:
        data = base64.b64decode(encrypted_message, validate=True)

        if len(data) < 32 or (len(data) - 16) % 16 != 0:
            raise ValueError("Invalid ciphertext.")

        iv = data[:16]
        ciphertext = data[16:]

        cipher = AES.new(_legacy_key(password), AES.MODE_CBC, iv)
        raw = unpad(cipher.decrypt(ciphertext), AES.block_size)

        if len(raw) < 32:
            raise ValueError("Invalid plaintext.")

        digest = raw[:32]
        message = raw[32:]

        if not hmac.compare_digest(
            digest, hashlib.sha256(message).digest()
        ):
            raise ValueError("Integrity verification failed.")

        return message.decode("utf-8")

    except Exception as exc:
        raise ValueError(
            "Unable to decrypt message. Check the password or data."
        ) from exc


# --------------------------------------------------
# NEW AUTHENTICATED BINARY ENCRYPTION
# --------------------------------------------------

def encrypt_bytes(data: bytes, password: str) -> bytes:
    """Encrypt binary data using AES-256-GCM."""
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=32,
        count=200000
    )

    nonce = get_random_bytes(NONCE_SIZE)

    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce,
        mac_len=TAG_SIZE
    )

    ciphertext, tag = cipher.encrypt_and_digest(data)

    return MAGIC + salt + nonce + tag + ciphertext


def decrypt_bytes(data: bytes, password: str) -> bytes:
    """Decrypt and authenticate binary data."""
    header_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE + TAG_SIZE

    if len(data) < header_size or not data.startswith(MAGIC):
        raise ValueError("Invalid encrypted binary data.")

    pos = len(MAGIC)

    salt = data[pos:pos + SALT_SIZE]
    pos += SALT_SIZE

    nonce = data[pos:pos + NONCE_SIZE]
    pos += NONCE_SIZE

    tag = data[pos:pos + TAG_SIZE]
    pos += TAG_SIZE

    ciphertext = data[pos:]

    key = PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=32,
        count=200000
    )

    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce,
        mac_len=TAG_SIZE
    )

    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise ValueError(
            "Authentication failed. Incorrect password or modified data."
        ) from exc


# --------------------------------------------------
# LARGE FILE ENCRYPTION — CHUNKED PROCESSING
# --------------------------------------------------

def encrypt_file(input_path, output_path, password):
    """Encrypt large files in 1 MB authenticated chunks."""
    salt = get_random_bytes(SALT_SIZE)

    key = PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=32,
        count=200000
    )

    with open(input_path, "rb") as source, open(output_path, "wb") as target:
        target.write(MAGIC)
        target.write(salt)

        index = 0

        while True:
            chunk = source.read(CHUNK_SIZE)

            if not chunk:
                break

            nonce = get_random_bytes(NONCE_SIZE)

            cipher = AES.new(
                key,
                AES.MODE_GCM,
                nonce=nonce,
                mac_len=TAG_SIZE
            )

            cipher.update(struct.pack(">Q", index))

            ciphertext, tag = cipher.encrypt_and_digest(chunk)

            target.write(struct.pack(">I", len(chunk)))
            target.write(nonce)
            target.write(tag)
            target.write(ciphertext)

            index += 1

        # End-of-file marker
        target.write(struct.pack(">I", 0))


def decrypt_file(input_path, output_path, password):
    """Decrypt large files one authenticated chunk at a time."""
    with open(input_path, "rb") as source, open(output_path, "wb") as target:

        if source.read(len(MAGIC)) != MAGIC:
            raise ValueError("Invalid encrypted file.")

        salt = source.read(SALT_SIZE)

        if len(salt) != SALT_SIZE:
            raise ValueError("Invalid encryption header.")

        key = PBKDF2(
            password.encode("utf-8"),
            salt,
            dkLen=32,
            count=200000
        )

        index = 0

        while True:
            length_data = source.read(4)

            if len(length_data) != 4:
                raise ValueError("Incomplete encrypted file.")

            length = struct.unpack(">I", length_data)[0]

            if length == 0:
                if source.read(1):
                    raise ValueError("Unexpected trailing data.")
                break

            if length > CHUNK_SIZE:
                raise ValueError("Invalid chunk size.")

            nonce = source.read(NONCE_SIZE)
            tag = source.read(TAG_SIZE)
            ciphertext = source.read(length)

            if (
                len(nonce) != NONCE_SIZE
                or len(tag) != TAG_SIZE
                or len(ciphertext) != length
            ):
                raise ValueError("Incomplete encrypted chunk.")

            cipher = AES.new(
                key,
                AES.MODE_GCM,
                nonce=nonce,
                mac_len=TAG_SIZE
            )

            cipher.update(struct.pack(">Q", index))

            try:
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError as exc:
                raise ValueError("File authentication failed.") from exc

            target.write(plaintext)
            index += 1

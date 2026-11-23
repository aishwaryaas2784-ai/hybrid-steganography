"""
messaging.py

Inbox-based messaging with:
- RSA-secured session-key exchange.
- AES-GCM encrypted file transfers in authenticated chunks.
- Image-only, audio-only, and hybrid carriers.
- Direct encrypted-file embedding in PCM WAV audio when capacity permits.
- Automatic encrypted-transfer fallback for files that do not fit.
- Safe file naming and message paths.
- Backward compatibility with existing HYBTRF01 transfers and embedded messages.
"""

import os
import json
import uuid
import base64
import shutil
import secrets
import datetime
import hashlib
import struct

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

from hybrid_pipeline import hide_message, extract_message
from audio_stego import encode_audio, decode_audio
from ai_scorer import score_image
from rsa_keys import encrypt_session_key, decrypt_session_key


BASE_DATA_DIR = "message_store"

# Keep small image/hybrid payloads bounded because the legacy text
# embedding pipeline represents these files as Base64 strings.
EMBED_FILE_LIMIT = 2 * 1024 * 1024

TRANSFER_CHUNK_SIZE = 1024 * 1024
TRANSFER_MAGIC = b"HYBTRF01"
TRANSFER_SALT_SIZE = 16
TRANSFER_NONCE_SIZE = 12
TRANSFER_TAG_SIZE = 16
TRANSFER_ITERATIONS = 250000


def _safe_name(filename: str) -> str:
    filename = os.path.basename(str(filename).replace("\\", "/"))
    filename = filename.strip()
    safe = "".join(c for c in filename if c.isalnum() or c in "._- ")
    safe = safe.strip(" .")
    return safe[:180] or "downloaded_file"


def _safe_msg_id(msg_id: str) -> str:
    msg_id = str(msg_id)
    if not msg_id or any(c not in "0123456789abcdef" for c in msg_id.lower()):
        raise ValueError("Invalid message ID.")
    return msg_id


def _inbox_dir(username: str) -> str:
    return os.path.join(BASE_DATA_DIR, _safe_name(username), "inbox")


def _derive_transfer_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=32,
        count=TRANSFER_ITERATIONS,
        hmac_hash_module=SHA256
    )


def _encrypt_transfer_file(source_path: str, encrypted_path: str, password: str) -> None:
    """Encrypt a file in independently authenticated AES-GCM chunks."""
    salt = secrets.token_bytes(TRANSFER_SALT_SIZE)
    key = _derive_transfer_key(password, salt)

    with open(source_path, "rb") as source, open(encrypted_path, "wb") as destination:
        destination.write(TRANSFER_MAGIC)
        destination.write(salt)
        chunk_index = 0

        while True:
            chunk = source.read(TRANSFER_CHUNK_SIZE)
            if not chunk:
                break

            nonce = secrets.token_bytes(TRANSFER_NONCE_SIZE)
            aad = struct.pack(">Q", chunk_index)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TRANSFER_TAG_SIZE)
            cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(chunk)

            destination.write(struct.pack(">I", len(ciphertext)))
            destination.write(nonce)
            destination.write(ciphertext)
            destination.write(tag)
            chunk_index += 1

        destination.write(struct.pack(">I", 0))


def _decrypt_transfer_file(encrypted_path: str, output_path: str, password: str) -> None:
    """Decrypt and authenticate a file chunk by chunk."""
    temporary_output = output_path + ".decrypting"

    try:
        with open(encrypted_path, "rb") as source:
            if source.read(len(TRANSFER_MAGIC)) != TRANSFER_MAGIC:
                raise ValueError("Unsupported encrypted transfer format.")

            salt = source.read(TRANSFER_SALT_SIZE)
            if len(salt) != TRANSFER_SALT_SIZE:
                raise ValueError("Encrypted transfer is incomplete.")

            key = _derive_transfer_key(password, salt)
            chunk_index = 0

            with open(temporary_output, "wb") as destination:
                while True:
                    length_data = source.read(4)
                    if len(length_data) != 4:
                        raise ValueError("Encrypted transfer ended unexpectedly.")

                    ciphertext_length = struct.unpack(">I", length_data)[0]

                    if ciphertext_length == 0:
                        break

                    if ciphertext_length > TRANSFER_CHUNK_SIZE:
                        raise ValueError("Invalid encrypted chunk size.")

                    nonce = source.read(TRANSFER_NONCE_SIZE)
                    ciphertext = source.read(ciphertext_length)
                    tag = source.read(TRANSFER_TAG_SIZE)

                    if (
                        len(nonce) != TRANSFER_NONCE_SIZE
                        or len(ciphertext) != ciphertext_length
                        or len(tag) != TRANSFER_TAG_SIZE
                    ):
                        raise ValueError("Encrypted transfer is incomplete.")

                    aad = struct.pack(">Q", chunk_index)
                    cipher = AES.new(
                        key,
                        AES.MODE_GCM,
                        nonce=nonce,
                        mac_len=TRANSFER_TAG_SIZE
                    )
                    cipher.update(aad)

                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    destination.write(plaintext)
                    chunk_index += 1

                if source.read(1):
                    raise ValueError("Unexpected data after encrypted transfer.")

        os.replace(temporary_output, output_path)

    except Exception:
        if os.path.exists(temporary_output):
            os.remove(temporary_output)
        raise


def build_secret_payload(secret_type: str, text: str = None, file_path: str = None) -> str:
    """Build the legacy text or small-file payload."""
    if secret_type == "text":
        if text is None or text == "":
            raise ValueError("Please enter a secret message.")
        return text

    if secret_type == "file":
        if not file_path or not os.path.isfile(file_path):
            raise FileNotFoundError("Secret file was not found.")

        if os.path.getsize(file_path) > EMBED_FILE_LIMIT:
            raise ValueError("File is too large for Base64-based image/hybrid embedding.")

        with open(file_path, "rb") as source:
            b64data = base64.b64encode(source.read()).decode("ascii")

        filename = _safe_name(os.path.basename(file_path))
        return f"FILE::{filename}::{b64data}"

    raise ValueError("Unsupported secret type.")


def parse_secret_payload(payload: str, output_dir: str) -> dict:
    """Decode text or a legacy embedded file payload."""
    os.makedirs(output_dir, exist_ok=True)

    if payload.startswith("FILE::"):
        try:
            _, filename, b64data = payload.split("::", 2)
            filename = _safe_name(filename)
            data = base64.b64decode(b64data, validate=True)
        except Exception as exc:
            raise ValueError("Invalid embedded file payload.") from exc

        out_path = os.path.join(output_dir, filename)

        with open(out_path, "wb") as destination:
            destination.write(data)

        return {
            "type": "file",
            "filename": filename,
            "path": out_path
        }

    return {
        "type": "text",
        "content": payload
    }


def _try_score_image(image_path: str) -> float:
    if not image_path or not os.path.isfile(image_path):
        return 0.0

    try:
        return round(float(score_image(image_path)), 4)
    except Exception:
        return 0.0


def _write_metadata(msg_dir: str, meta: dict) -> None:
    meta_path = os.path.join(msg_dir, "meta.json")
    temporary_path = meta_path + ".tmp"

    with open(temporary_path, "w", encoding="utf-8") as destination:
        json.dump(meta, destination, indent=2)

    os.replace(temporary_path, meta_path)


def send_message(
    sender: str,
    recipient: str,
    secret_type: str,
    cover_image_path: str = None,
    secret_text: str = None,
    secret_file_path: str = None,
    cover_audio_path: str = None,
    embedding_method: str = "lsb",
    carrier_type: str = None
) -> dict:
    """Send text or files using image, audio, or hybrid carriers."""

    if not sender or not recipient:
        raise ValueError("Sender and recipient are required.")

    if sender == recipient:
        raise ValueError("Sender and recipient must be different.")

    if secret_type not in ("text", "file"):
        raise ValueError("Secret type must be 'text' or 'file'.")

    if carrier_type:
        carrier_type = carrier_type.lower().strip()
    elif cover_image_path and cover_audio_path:
        carrier_type = "hybrid"
    elif cover_image_path:
        carrier_type = "image"
    elif cover_audio_path:
        carrier_type = "audio"
    else:
        raise ValueError("Choose an image or audio cover file.")

    if carrier_type not in ("image", "audio", "hybrid"):
        raise ValueError("Carrier must be 'image', 'audio', or 'hybrid'.")

    if carrier_type in ("image", "hybrid"):
        if not cover_image_path or not os.path.isfile(cover_image_path):
            raise FileNotFoundError("A valid cover image is required.")

    if carrier_type in ("audio", "hybrid"):
        if not cover_audio_path or not os.path.isfile(cover_audio_path):
            raise FileNotFoundError("A valid cover audio file is required.")

        if os.path.splitext(cover_audio_path)[1].lower() != ".wav":
            raise ValueError("Audio carrier must be an uncompressed PCM WAV file.")

    if secret_type == "text" and not secret_text:
        raise ValueError("Please enter a secret message.")

    if secret_type == "file" and (
        not secret_file_path or not os.path.isfile(secret_file_path)
    ):
        raise FileNotFoundError("Secret file was not found.")

    msg_id = uuid.uuid4().hex[:10]

    recipient_dir = _inbox_dir(recipient)
    os.makedirs(recipient_dir, exist_ok=True)

    msg_dir = os.path.join(recipient_dir, msg_id)
    os.makedirs(msg_dir, exist_ok=False)

    session_password = secrets.token_hex(32)

    try:
        encrypted_session_key = encrypt_session_key(session_password, recipient)

        transfer_mode = "embedded"
        final_filename = None
        security_score = 0.0
        original_filename = None
        original_file_size = 0
        used_audio_layer = carrier_type == "hybrid"

        def embed_payload(payload):
            return hide_message(
                secret_message=payload,
                password=session_password,
                cover_image_path=cover_image_path,
                cover_audio_path=cover_audio_path,
                output_dir=msg_dir,
                embedding_method=embedding_method,
                carrier_type=carrier_type
            )

        if secret_type == "text":
            result = embed_payload(
                build_secret_payload("text", text=secret_text)
            )

            final_filename = os.path.basename(result["final_path"])
            security_score = _try_score_image(
                result.get("stego_image_path")
            )

        else:
            original_filename = _safe_name(
                os.path.basename(secret_file_path)
            )
            original_file_size = os.path.getsize(secret_file_path)

            embedded_successfully = False

            # Audio-only: encrypt the original file in chunks and try to
            # embed the encrypted payload directly inside the cover WAV.
            if carrier_type == "audio":
                encrypted_payload_path = os.path.join(
                    msg_dir,
                    f"payload_{msg_id}.hyb"
                )

                stego_audio_path = os.path.join(
                    msg_dir,
                    f"stego_audio_{msg_id}.wav"
                )

                try:
                    _encrypt_transfer_file(
                        secret_file_path,
                        encrypted_payload_path,
                        session_password
                    )

                    encode_audio(
                        cover_audio_path,
                        encrypted_payload_path,
                        stego_audio_path
                    )

                    final_filename = os.path.basename(stego_audio_path)
                    transfer_mode = "embedded_audio_file"
                    embedded_successfully = True

                except Exception as exc:
                    print(
                        "Encrypted audio embedding unavailable; "
                        f"using secure transfer: {exc}"
                    )

                finally:
                    if os.path.exists(encrypted_payload_path):
                        os.remove(encrypted_payload_path)

            # Small image/hybrid files can use the existing embedding method.
            elif original_file_size <= EMBED_FILE_LIMIT:
                try:
                    result = embed_payload(
                        build_secret_payload(
                            "file",
                            file_path=secret_file_path
                        )
                    )

                    final_filename = os.path.basename(result["final_path"])
                    security_score = _try_score_image(
                        result.get("stego_image_path")
                    )

                    embedded_successfully = True

                except Exception as exc:
                    print(
                        "Embedding unavailable; "
                        f"switching to encrypted transfer: {exc}"
                    )

            # If embedding is not possible, use encrypted file transfer.
            if not embedded_successfully:
                transfer_mode = "encrypted_transfer"

                encrypted_filename = f"transfer_{msg_id}.hyb"
                encrypted_path = os.path.join(
                    msg_dir,
                    encrypted_filename
                )

                _encrypt_transfer_file(
                    secret_file_path,
                    encrypted_path,
                    session_password
                )

                final_filename = encrypted_filename

        # Retain the original cover audio separately if the secret file
        # could not fit inside the audio carrier.
        cover_audio_filename = None

        if carrier_type == "audio" and transfer_mode == "encrypted_transfer":
            cover_audio_filename = f"cover_audio_{msg_id}.wav"

            shutil.copy2(
                cover_audio_path,
                os.path.join(msg_dir, cover_audio_filename)
            )

        meta = {
            "msg_id": msg_id,
            "sender": sender,
            "recipient": recipient,
            "secret_type": secret_type,
            "transfer_mode": transfer_mode,
            "carrier_type": carrier_type,
            "used_audio_layer": used_audio_layer,
            "embedding_method": embedding_method,
            "final_filename": final_filename,
            "cover_audio_filename": cover_audio_filename,
            "original_filename": original_filename,
            "original_file_size": original_file_size,
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            "encrypted_session_key": encrypted_session_key,
            "security_score": security_score
        }

        _write_metadata(msg_dir, meta)
        _record_recipient(sender, recipient)

        return meta

    except Exception:
        if os.path.isdir(msg_dir):
            shutil.rmtree(msg_dir, ignore_errors=True)
        raise


def list_inbox(username: str) -> list:
    inbox = _inbox_dir(username)

    if not os.path.exists(inbox):
        return []

    messages = []

    for msg_id in os.listdir(inbox):
        meta_path = os.path.join(
            inbox,
            msg_id,
            "meta.json"
        )

        if not os.path.isfile(meta_path):
            continue

        try:
            with open(meta_path, encoding="utf-8") as source:
                messages.append(json.load(source))

        except (OSError, json.JSONDecodeError):
            continue

    messages.sort(
        key=lambda message: message.get("timestamp", ""),
        reverse=True
    )

    return messages


def get_final_path(username: str, msg_id: str, filename: str) -> str:
    msg_id = _safe_msg_id(msg_id)
    filename = _safe_name(filename)

    msg_dir = os.path.abspath(
        os.path.join(_inbox_dir(username), msg_id)
    )

    path = os.path.abspath(
        os.path.join(msg_dir, filename)
    )

    if os.path.commonpath([msg_dir, path]) != msg_dir:
        raise ValueError("Invalid file path.")

    return path


def decode_inbox_message(username: str, msg_id: str) -> dict:
    """Decode embedded messages, encrypted audio files, or transfers."""

    msg_id = _safe_msg_id(msg_id)

    msg_dir = os.path.abspath(
        os.path.join(_inbox_dir(username), msg_id)
    )

    meta_path = os.path.join(msg_dir, "meta.json")

    if not os.path.isfile(meta_path):
        raise FileNotFoundError("Message metadata was not found.")

    with open(meta_path, encoding="utf-8") as source:
        meta = json.load(source)

    session_password = decrypt_session_key(
        meta["encrypted_session_key"],
        username
    )

    final_path = get_final_path(
        username,
        msg_id,
        meta["final_filename"]
    )

    if not os.path.isfile(final_path):
        raise FileNotFoundError(
            "Message carrier or transfer file is missing."
        )

    transfer_mode = meta.get("transfer_mode", "embedded")

    if transfer_mode in ("encrypted_transfer", "embedded_audio_file"):
        filename = _safe_name(
            meta.get("original_filename") or "downloaded_file"
        )

        output_path = os.path.join(msg_dir, filename)

        if transfer_mode == "encrypted_transfer":
            encrypted_source = final_path

        else:
            encrypted_source = os.path.join(
                msg_dir,
                f"extracted_payload_{msg_id}.hyb"
            )

            try:
                decode_audio(
                    final_path,
                    encrypted_source
                )

            except Exception:
                if os.path.exists(encrypted_source):
                    os.remove(encrypted_source)
                raise

        try:
            _decrypt_transfer_file(
                encrypted_source,
                output_path,
                session_password
            )

        finally:
            if (
                transfer_mode == "embedded_audio_file"
                and os.path.exists(encrypted_source)
            ):
                os.remove(encrypted_source)

        return {
            "type": "file",
            "filename": filename,
            "path": output_path
        }

    carrier_type = meta.get("carrier_type")

    if not carrier_type:
        carrier_type = (
            "hybrid"
            if meta.get("used_audio_layer", False)
            else "image"
        )

    payload = extract_message(
        final_path,
        session_password,
        meta.get("used_audio_layer", False),
        output_dir=msg_dir,
        embedding_method=meta.get("embedding_method", "lsb"),
        carrier_type=carrier_type
    )

    return parse_secret_payload(payload, msg_dir)


def delete_message(username: str, msg_id: str) -> bool:
    msg_id = _safe_msg_id(msg_id)

    msg_dir = os.path.abspath(
        os.path.join(_inbox_dir(username), msg_id)
    )

    inbox_dir = os.path.abspath(
        _inbox_dir(username)
    )

    if os.path.commonpath([inbox_dir, msg_dir]) != inbox_dir:
        raise ValueError("Invalid message directory.")

    if os.path.isdir(msg_dir):
        shutil.rmtree(msg_dir)
        return True

    return False


def get_recent_recipients(sender: str, limit: int = 8) -> list:
    log_path = os.path.join(
        BASE_DATA_DIR,
        _safe_name(sender),
        "sent_log.json"
    )

    if not os.path.isfile(log_path):
        return []

    try:
        with open(log_path, encoding="utf-8") as source:
            log = json.load(source)

        return log[:max(0, int(limit))]

    except (OSError, json.JSONDecodeError, TypeError):
        return []


def _record_recipient(sender: str, recipient: str) -> None:
    sender_dir = os.path.join(
        BASE_DATA_DIR,
        _safe_name(sender)
    )

    os.makedirs(sender_dir, exist_ok=True)

    log_path = os.path.join(
        sender_dir,
        "sent_log.json"
    )

    log = []

    if os.path.isfile(log_path):
        try:
            with open(log_path, encoding="utf-8") as source:
                log = json.load(source)

        except (OSError, json.JSONDecodeError):
            log = []

    log = [r for r in log if r != recipient]
    log.insert(0, recipient)
    log = log[:20]

    temporary_path = log_path + ".tmp"

    with open(temporary_path, "w", encoding="utf-8") as destination:
        json.dump(log, destination, indent=2)

    os.replace(temporary_path, log_path)
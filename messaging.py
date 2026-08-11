"""
messaging.py
Inbox-based messaging layer with RSA-secured automatic key exchange,
selectable embedding method (LSB or DWT), and recent-recipient contacts.
"""

import os
import json
import uuid
import base64
import shutil
import secrets
import datetime

from hybrid_pipeline import hide_message, extract_message
from ai_scorer import score_image
from rsa_keys import encrypt_session_key, decrypt_session_key

BASE_DATA_DIR = "message_store"


def _inbox_dir(username: str) -> str:
    return os.path.join(BASE_DATA_DIR, username, "inbox")


def build_secret_payload(secret_type: str, text: str = None, file_path: str = None) -> str:
    if secret_type == "text":
        return text
    else:
        with open(file_path, "rb") as f:
            data = f.read()
        b64 = base64.b64encode(data).decode("utf-8")
        filename = os.path.basename(file_path)
        return f"FILE::{filename}::{b64}"


def parse_secret_payload(payload: str, output_dir: str) -> dict:
    if payload.startswith("FILE::"):
        _, filename, b64data = payload.split("::", 2)
        data = base64.b64decode(b64data)
        out_path = os.path.join(output_dir, filename)
        with open(out_path, "wb") as f:
            f.write(data)
        return {"type": "file", "filename": filename, "path": out_path}
    else:
        return {"type": "text", "content": payload}


def send_message(sender: str, recipient: str, secret_type: str,
                  cover_image_path: str, secret_text: str = None, secret_file_path: str = None,
                  cover_audio_path: str = None, embedding_method: str = "lsb") -> dict:
    msg_id = uuid.uuid4().hex[:10]
    msg_dir = os.path.join(_inbox_dir(recipient), msg_id)
    os.makedirs(msg_dir, exist_ok=True)

    session_password = secrets.token_hex(16)

    payload = build_secret_payload(secret_type, text=secret_text, file_path=secret_file_path)

    result = hide_message(
        secret_message=payload,
        password=session_password,
        cover_image_path=cover_image_path,
        cover_audio_path=cover_audio_path,
        output_dir=msg_dir,
        embedding_method=embedding_method
    )

    encrypted_session_key = encrypt_session_key(session_password, recipient)

    security_score = score_image(result["stego_image_path"])
    final_filename = os.path.basename(result["final_path"])

    meta = {
        "msg_id": msg_id,
        "sender": sender,
        "recipient": recipient,
        "secret_type": secret_type,
        "used_audio_layer": result["used_audio_layer"],
        "embedding_method": embedding_method,
        "final_filename": final_filename,
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "encrypted_session_key": encrypted_session_key,
        "security_score": round(security_score, 4)
    }

    with open(os.path.join(msg_dir, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    _record_recipient(sender, recipient)
    return meta


def list_inbox(username: str) -> list:
    inbox = _inbox_dir(username)
    if not os.path.exists(inbox):
        return []
    messages = []
    for msg_id in os.listdir(inbox):
        meta_path = os.path.join(inbox, msg_id, "meta.json")
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                messages.append(json.load(f))
    messages.sort(key=lambda m: m["timestamp"], reverse=True)
    return messages


def get_final_path(username: str, msg_id: str, filename: str) -> str:
    return os.path.join(_inbox_dir(username), msg_id, filename)


def decode_inbox_message(username: str, msg_id: str) -> dict:
    msg_dir = os.path.join(_inbox_dir(username), msg_id)
    with open(os.path.join(msg_dir, "meta.json")) as f:
        meta = json.load(f)

    session_password = decrypt_session_key(meta["encrypted_session_key"], username)

    final_path = os.path.join(msg_dir, meta["final_filename"])
    payload = extract_message(final_path, session_password, meta["used_audio_layer"],
                               output_dir=msg_dir, embedding_method=meta.get("embedding_method", "lsb"))

    return parse_secret_payload(payload, msg_dir)


def delete_message(username: str, msg_id: str) -> bool:
    msg_dir = os.path.join(_inbox_dir(username), msg_id)
    if os.path.exists(msg_dir):
        shutil.rmtree(msg_dir)
        return True
    return False


def get_recent_recipients(sender: str, limit: int = 8) -> list:
    log_path = os.path.join(BASE_DATA_DIR, sender, "sent_log.json")
    if not os.path.exists(log_path):
        return []
    with open(log_path) as f:
        log = json.load(f)
    return log[:limit]


def _record_recipient(sender: str, recipient: str):
    sender_dir = os.path.join(BASE_DATA_DIR, sender)
    os.makedirs(sender_dir, exist_ok=True)
    log_path = os.path.join(sender_dir, "sent_log.json")

    log = []
    if os.path.exists(log_path):
        with open(log_path) as f:
            log = json.load(f)

    log = [r for r in log if r != recipient]
    log.insert(0, recipient)
    log = log[:20]

    with open(log_path, "w") as f:
        json.dump(log, f, indent=2)
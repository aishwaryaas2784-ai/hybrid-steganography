"""
app.py
Flask messaging app with account login, RSA key exchange, selectable
embedding method (LSB / DWT), and recent-recipient autocomplete.
"""

import os
import uuid
from flask import Flask, render_template, request, session, redirect, url_for, flash, send_file

import messaging
import users
from rsa_keys import generate_user_keypair

app = Flask(__name__)
app.secret_key = "change_this_secret_key_2026"

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        success, msg = users.register_user(username, password, full_name, email, phone)
        if not success:
            flash(msg)
            return redirect(url_for("signup"))

        generate_user_keypair(username.strip().lower())
        flash("Account created! Please log in.")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Please enter both username and password.")
            return redirect(url_for("login"))

        success, msg = users.verify_login(username, password)
        if not success:
            flash(msg)
            return redirect(url_for("login"))

        clean_username = username.strip().lower()
        session["username"] = clean_username
        generate_user_keypair(clean_username)
        return redirect(url_for("home"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    if "username" not in session:
        return redirect(url_for("login"))
    inbox = messaging.list_inbox(session["username"])
    user_info = users.get_user_info(session["username"])
    recent_recipients = messaging.get_recent_recipients(session["username"])
    return render_template("home.html", username=session["username"],
                            full_name=user_info.get("full_name", session["username"]),
                            inbox=inbox, recent_recipients=recent_recipients)


@app.route("/send", methods=["POST"])
def send():
    if "username" not in session:
        return redirect(url_for("login"))

    try:
        recipient = request.form.get("recipient", "").strip().lower()
        secret_type = request.form.get("secret_type", "text")
        embedding_method = request.form.get("embedding_method", "lsb")
        cover_image = request.files.get("cover_image")
        cover_audio = request.files.get("cover_audio")
        secret_text = request.form.get("secret_message", "").strip()
        secret_file = request.files.get("secret_file")

        if not recipient or not cover_image or cover_image.filename == "":
            flash("Recipient and cover image are required.")
            return redirect(url_for("home"))

        if not users.user_exists(recipient):
            flash(f"No registered account found for '{recipient}'. They need to sign up first.")
            return redirect(url_for("home"))

        if secret_type == "text" and not secret_text:
            flash("Please type a secret message.")
            return redirect(url_for("home"))
        if secret_type == "file" and (not secret_file or secret_file.filename == ""):
            flash("Please choose a file to hide.")
            return redirect(url_for("home"))

        tmp_dir = os.path.join(UPLOAD_DIR, f"tmp_{uuid.uuid4().hex[:8]}")
        os.makedirs(tmp_dir, exist_ok=True)

        cover_image_path = os.path.join(tmp_dir, "cover.png")
        cover_image.save(cover_image_path)

        cover_audio_path = None
        if cover_audio and cover_audio.filename != "":
            cover_audio_path = os.path.join(tmp_dir, "cover.wav")
            cover_audio.save(cover_audio_path)

        secret_file_path = None
        if secret_type == "file":
            secret_file_path = os.path.join(tmp_dir, secret_file.filename)
            secret_file.save(secret_file_path)

        meta = messaging.send_message(
            sender=session["username"],
            recipient=recipient,
            secret_type=secret_type,
            cover_image_path=cover_image_path,
            secret_text=secret_text if secret_type == "text" else None,
            secret_file_path=secret_file_path,
            cover_audio_path=cover_audio_path,
            embedding_method=embedding_method
        )

        layer_note = "hybrid image+audio" if meta["used_audio_layer"] else "image-only"
        method_note = "DWT (transform domain)" if embedding_method == "dwt" else "Chaotic-Map LSB (spatial domain)"
        flash(f"Message sent to {recipient} ({layer_note}, {method_note}), secured via RSA key exchange.")
        return redirect(url_for("home"))

    except Exception as e:
        flash(f"Error sending message: {str(e)}")
        return redirect(url_for("home"))


@app.route("/decode/<msg_id>", methods=["POST"])
def decode_inbox(msg_id):
    if "username" not in session:
        return redirect(url_for("home"))
    try:
        recovered = messaging.decode_inbox_message(session["username"], msg_id)
        inbox = messaging.list_inbox(session["username"])
        user_info = users.get_user_info(session["username"])
        recent_recipients = messaging.get_recent_recipients(session["username"])
        return render_template("home.html", username=session["username"],
                                full_name=user_info.get("full_name", session["username"]),
                                inbox=inbox, recent_recipients=recent_recipients,
                                decoded_msg_id=msg_id, recovered=recovered)
    except Exception as e:
        flash(f"Error decoding: {str(e)}")
        return redirect(url_for("home"))


@app.route("/delete/<msg_id>", methods=["POST"])
def delete_message(msg_id):
    if "username" not in session:
        return redirect(url_for("login"))
    messaging.delete_message(session["username"], msg_id)
    flash("Message deleted.")
    return redirect(url_for("home"))


@app.route("/download_final/<msg_id>")
def download_final(msg_id):
    if "username" not in session:
        return redirect(url_for("login"))
    inbox = messaging.list_inbox(session["username"])
    meta = next((m for m in inbox if m["msg_id"] == msg_id), None)
    if not meta:
        flash("Message not found.")
        return redirect(url_for("home"))
    path = messaging.get_final_path(session["username"], msg_id, meta["final_filename"])
    return send_file(path, as_attachment=True)


@app.route("/download_recovered/<msg_id>/<filename>")
def download_recovered(msg_id, filename):
    if "username" not in session:
        return redirect(url_for("login"))
    path = messaging.get_final_path(session["username"], msg_id, filename)
    return send_file(path, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False)
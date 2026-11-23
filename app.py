import os
import uuid
import shutil
import subprocess
import mimetypes
import hashlib

from flask import (
    Flask,
    render_template,
    request,
    session,
    redirect,
    url_for,
    flash,
    send_file
)

from werkzeug.utils import secure_filename

import messaging
import users
from rsa_keys import generate_user_keypair


app = Flask(__name__)
app.secret_key = "change_this_secret_key_2026"

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Maximum upload size: 4 GB by default.
# This can be changed using the environment variable.
MAX_UPLOAD_BYTES = int(
    os.environ.get(
        "HYBRID_STEGO_MAX_UPLOAD_BYTES",
        str(4 * 1024 * 1024 * 1024)
    )
)

app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


# --------------------------------------------------
# AUDIO CONVERSION
# --------------------------------------------------

def get_ffmpeg_path():
    """Find FFmpeg installed through imageio-ffmpeg."""

    try:
        import imageio_ffmpeg
        return imageio_ffmpeg.get_ffmpeg_exe()

    except Exception as exc:
        raise RuntimeError(
            "Audio conversion package is unavailable. "
            "Run: pip install imageio-ffmpeg"
        ) from exc


def convert_audio_to_wav(input_path, output_path):
    """Convert audio into uncompressed PCM WAV."""

    ffmpeg_path = get_ffmpeg_path()

    command = [
        ffmpeg_path,
        "-y",
        "-nostdin",
        "-i", input_path,
        "-vn",
        "-acodec", "pcm_s16le",
        output_path
    ]

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0 or not os.path.exists(output_path):

        error_text = (
            result.stderr[-1500:]
            if result.stderr
            else "Unknown conversion error"
        )

        raise RuntimeError(
            "Could not convert the selected audio file. "
            "Please choose a valid audio file. "
            + error_text
        )

    if os.path.getsize(output_path) == 0:
        raise RuntimeError("The converted audio file is empty.")


def save_uploaded_file(uploaded_file, destination):
    """Save an uploaded file safely."""

    if not uploaded_file or not uploaded_file.filename:
        raise ValueError("Please select a file.")

    original_name = secure_filename(uploaded_file.filename)

    if not original_name:
        raise ValueError("The selected filename is invalid.")

    uploaded_file.save(destination)

    return original_name


@app.errorhandler(413)
def upload_too_large(_error):

    flash(
        "The selected upload exceeds the configured limit "
        f"({MAX_UPLOAD_BYTES / (1024 ** 3):.1f} GB). "
        "You can change HYBRID_STEGO_MAX_UPLOAD_BYTES if your disk "
        "space and system resources allow it."
    )

    return redirect(
        url_for("home" if "username" in session else "login")
    )


# --------------------------------------------------
# SIGNUP
# --------------------------------------------------

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get(
            "password", ""
        ).strip()

        full_name = request.form.get(
            "full_name", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip()

        phone = request.form.get(
            "phone", ""
        ).strip()

        success, msg = users.register_user(
            username,
            password,
            full_name,
            email,
            phone
        )

        if not success:
            flash(msg)
            return redirect(url_for("signup"))

        generate_user_keypair(username.strip().lower())

        flash("Account created! Please log in.")

        return redirect(url_for("login"))

    return render_template("signup.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get(
            "password", ""
        ).strip()

        if not username or not password:

            flash("Please enter both username and password.")

            return redirect(url_for("login"))

        success, msg = users.verify_login(
            username,
            password
        )

        if not success:

            flash(msg)

            return redirect(url_for("login"))

        clean_username = username.strip().lower()

        session["username"] = clean_username

        # Reuse existing RSA keys.
        generate_user_keypair(clean_username)

        return redirect(url_for("home"))

    return render_template("login.html")


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():

    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]

    user_info = users.get_user_info(username)

    inbox_count = len(
        messaging.list_inbox(username)
    )

    return render_template(
        "home.html",
        username=username,
        full_name=user_info.get("full_name", username),
        inbox_count=inbox_count
    )


# --------------------------------------------------
# INBOX PAGE
# --------------------------------------------------

@app.route("/inbox")
def inbox_page():

    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]

    inbox = messaging.list_inbox(username)

    user_info = users.get_user_info(username)

    return render_template(
        "inbox.html",
        username=username,
        full_name=user_info.get("full_name", username),
        inbox=inbox
    )


# --------------------------------------------------
# SEND MESSAGE
# --------------------------------------------------

@app.route("/send", methods=["POST"])
def send():

    if "username" not in session:
        return redirect(url_for("login"))

    tmp_dir = None

    try:

        sender = session["username"]

        recipient = request.form.get(
            "recipient", ""
        ).strip().lower()

        secret_type = request.form.get(
            "secret_type", "text"
        ).strip().lower()

        embedding_method = request.form.get(
            "embedding_method", "lsb"
        ).strip().lower()

        carrier_type = request.form.get(
            "carrier_type", "image"
        ).strip().lower()

        cover_image = request.files.get("cover_image")

        cover_audio = request.files.get("cover_audio")

        secret_text = request.form.get(
            "secret_message", ""
        ).strip()

        secret_file = request.files.get("secret_file")

        has_image = bool(
            cover_image and cover_image.filename
        )

        has_audio = bool(
            cover_audio and cover_audio.filename
        )

        # Validate recipient.

        if not recipient:

            flash("Please enter the recipient username.")

            return redirect(url_for("home"))

        if not users.user_exists(recipient):

            flash(
                f"No registered account found for '{recipient}'. "
                "They need to sign up first."
            )

            return redirect(url_for("home"))

        # Validate secret type.

        if secret_type not in ("text", "file"):

            flash("Invalid secret message type.")

            return redirect(url_for("home"))

        # Validate embedding method.

        if embedding_method not in ("lsb", "dwt"):

            flash("Please select a valid embedding method.")

            return redirect(url_for("home"))

        # Validate carrier type.

        if carrier_type not in ("image", "audio", "hybrid"):

            flash(
                "Please select Image only, Audio only, "
                "or Image + Audio."
            )

            return redirect(url_for("home"))

        if carrier_type == "image" and not has_image:

            flash("Please choose a PNG cover image.")

            return redirect(url_for("home"))

        if carrier_type == "audio" and not has_audio:

            flash("Please choose an audio cover file.")

            return redirect(url_for("home"))

        if carrier_type == "hybrid" and not (
            has_image and has_audio
        ):

            flash(
                "Hybrid mode requires both a PNG image "
                "and an audio file."
            )

            return redirect(url_for("home"))

        if carrier_type in ("image", "hybrid"):

            if not cover_image.filename.lower().endswith(".png"):

                flash("The cover image must be a PNG file.")

                return redirect(url_for("home"))

        # Validate secret content.

        if secret_type == "text" and not secret_text:

            flash("Please type a secret message.")

            return redirect(url_for("home"))

        if secret_type == "file" and (
            not secret_file or not secret_file.filename
        ):

            flash("Please choose a secret file.")

            return redirect(url_for("home"))

        # Create temporary upload directory.

        tmp_dir = os.path.join(
            UPLOAD_DIR,
            f"tmp_{uuid.uuid4().hex}"
        )

        os.makedirs(tmp_dir, exist_ok=True)

        # Save image if required.

        cover_image_path = None

        if carrier_type in ("image", "hybrid"):

            cover_image_path = os.path.join(
                tmp_dir,
                "cover.png"
            )

            save_uploaded_file(
                cover_image,
                cover_image_path
            )

        # Save and convert audio if required.

        cover_audio_path = None

        if carrier_type in ("audio", "hybrid"):

            original_audio_name = secure_filename(
                cover_audio.filename
            )

            if not original_audio_name:

                raise ValueError(
                    "The selected audio filename is invalid."
                )

            original_audio_path = os.path.join(
                tmp_dir,
                original_audio_name
            )

            cover_audio.save(original_audio_path)

            converted_audio_path = os.path.join(
                tmp_dir,
                "cover_audio_converted.wav"
            )

            convert_audio_to_wav(
                original_audio_path,
                converted_audio_path
            )

            cover_audio_path = converted_audio_path

        # Save secret file if required.

        secret_file_path = None

        if secret_type == "file":

            original_secret_name = secure_filename(
                secret_file.filename
            )

            if not original_secret_name:

                raise ValueError(
                    "The selected secret filename is invalid."
                )

            secret_file_path = os.path.join(
                tmp_dir,
                original_secret_name
            )

            secret_file.save(secret_file_path)

        # Send through the existing messaging pipeline.

        meta = messaging.send_message(
            sender=sender,
            recipient=recipient,
            secret_type=secret_type,
            cover_image_path=cover_image_path,
            secret_text=(
                secret_text
                if secret_type == "text"
                else None
            ),
            secret_file_path=secret_file_path,
            cover_audio_path=cover_audio_path,
            embedding_method=embedding_method,
            carrier_type=carrier_type
        )

        if meta.get("transfer_mode") == "encrypted_transfer":

            flash(
                f"Message sent to {recipient} using "
                "secure encrypted file transfer."
            )

        else:

            carrier_label = {
                "image": "image-only",
                "audio": "audio-only",
                "hybrid": "hybrid image+audio"
            }[carrier_type]

            method_note = (
                "DWT (transform domain)"
                if embedding_method == "dwt"
                else "Chaotic-Map LSB (spatial domain)"
            )

            flash(
                f"Message sent to {recipient} "
                f"({carrier_label}, {method_note}), "
                "secured via RSA key exchange."
            )

        return redirect(url_for("home"))

    except Exception as exc:

        flash(f"Error sending message: {str(exc)}")

        return redirect(url_for("home"))

    finally:

        # Remove only temporary files from this send operation.

        if tmp_dir and os.path.isdir(tmp_dir):

            shutil.rmtree(
                tmp_dir,
                ignore_errors=True
            )


# --------------------------------------------------
# DECODE INBOX MESSAGE
# --------------------------------------------------

@app.route("/decode/<msg_id>", methods=["POST"])
def decode_inbox(msg_id):

    if "username" not in session:
        return redirect(url_for("login"))

    try:

        recovered = messaging.decode_inbox_message(
            session["username"],
            msg_id
        )

        inbox = messaging.list_inbox(
            session["username"]
        )

        user_info = users.get_user_info(
            session["username"]
        )

        return render_template(
            "inbox.html",
            username=session["username"],
            full_name=user_info.get(
                "full_name",
                session["username"]
            ),
            inbox=inbox,
            decoded_msg_id=msg_id,
            recovered=recovered
        )

    except Exception as exc:

        flash(f"Error decoding: {str(exc)}")

        return redirect(url_for("inbox_page"))


# --------------------------------------------------
# DELETE MESSAGE
# --------------------------------------------------

@app.route("/delete/<msg_id>", methods=["POST"])
def delete_message(msg_id):

    if "username" not in session:
        return redirect(url_for("login"))

    messaging.delete_message(
        session["username"],
        msg_id
    )

    flash("Message deleted.")

    return redirect(url_for("inbox_page"))


# --------------------------------------------------
# BROWSER AUDIO PLAYBACK HELPER
# --------------------------------------------------

def get_browser_playback_file(source_path, message_dir):
    """
    Return an audio file suitable for common desktop browsers.

    Keep the original recovered file untouched for download.
    WAV/MP3/OGG/M4A/AAC are served directly.
    Other formats are converted to a cached MP3 with FFmpeg.
    """

    extension = os.path.splitext(source_path)[1].lower()

    browser_friendly = {
        ".wav": "audio/wav",
        ".mp3": "audio/mpeg",
        ".ogg": "audio/ogg",
        ".oga": "audio/ogg",
        ".m4a": "audio/mp4",
        ".aac": "audio/aac",
        ".mp4": "audio/mp4",
        ".webm": "audio/webm"
    }

    if extension in browser_friendly:
        return source_path, browser_friendly[extension]

    stat = os.stat(source_path)

    cache_key = hashlib.sha256(
        (
            f"{os.path.abspath(source_path)}|"
            f"{stat.st_size}|{stat.st_mtime_ns}"
        ).encode("utf-8")
    ).hexdigest()[:24]

    cache_dir = os.path.join(
        message_dir,
        ".audio_preview_cache"
    )

    os.makedirs(cache_dir, exist_ok=True)

    converted_path = os.path.join(
        cache_dir,
        f"{cache_key}.mp3"
    )

    if (
        not os.path.isfile(converted_path)
        or os.path.getsize(converted_path) == 0
    ):

        temporary_path = converted_path + ".tmp.mp3"

        command = [
            get_ffmpeg_path(),
            "-y",
            "-nostdin",
            "-i", source_path,
            "-vn",
            "-codec:a", "libmp3lame",
            "-b:a", "192k",
            temporary_path
        ]

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if (
            result.returncode != 0
            or not os.path.isfile(temporary_path)
        ):

            if os.path.exists(temporary_path):
                os.remove(temporary_path)

            detail = (
                result.stderr[-1000:]
                if result.stderr
                else "Unknown FFmpeg error"
            )

            raise RuntimeError(
                "Could not prepare browser audio playback. "
                + detail
            )

        os.replace(
            temporary_path,
            converted_path
        )

    return converted_path, "audio/mpeg"


# --------------------------------------------------
# PREVIEW RECEIVED COVER AUDIO
# --------------------------------------------------

@app.route("/preview_final/<msg_id>")
def preview_final(msg_id):

    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]

    inbox = messaging.list_inbox(username)

    meta = next(
        (
            item for item in inbox
            if item.get("msg_id") == msg_id
        ),
        None
    )

    if not meta:

        flash("Message not found.")

        return redirect(url_for("inbox_page"))

    try:

        filename = (
            meta.get("cover_audio_filename")
            or meta.get("final_filename", "")
        )

        path = messaging.get_final_path(
            username,
            msg_id,
            filename
        )

        if not os.path.isfile(path):

            flash("Received audio file not found.")

            return redirect(url_for("inbox_page"))

        mime_type, _ = mimetypes.guess_type(filename)

        if not mime_type or not mime_type.startswith("audio/"):

            flash("This received file is not an audio file.")

            return redirect(url_for("inbox_page"))

        return send_file(
            path,
            mimetype=mime_type,
            as_attachment=False,
            conditional=True
        )

    except Exception as exc:

        flash(f"Audio preview error: {str(exc)}")

        return redirect(url_for("inbox_page"))


# --------------------------------------------------
# PREVIEW RECOVERED SECRET AUDIO
# --------------------------------------------------

@app.route(
    "/preview_recovered/<msg_id>/<path:filename>"
)
def preview_recovered(msg_id, filename):

    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]

    try:

        inbox = messaging.list_inbox(username)

        meta = next(
            (
                item for item in inbox
                if item.get("msg_id") == msg_id
            ),
            None
        )

        if not meta:

            flash("Message not found.")

            return redirect(url_for("inbox_page"))

        safe_filename = secure_filename(filename)

        if not safe_filename or safe_filename != filename:

            flash("Invalid filename.")

            return redirect(url_for("inbox_page"))

        path = messaging.get_final_path(
            username,
            msg_id,
            safe_filename
        )

        if not os.path.isfile(path):

            flash(
                "Recovered audio not found. "
                "Please decode the message first."
            )

            return redirect(url_for("inbox_page"))

        mime_type, _ = mimetypes.guess_type(safe_filename)

        if not mime_type or not mime_type.startswith("audio/"):

            flash("The recovered file is not an audio file.")

            return redirect(url_for("inbox_page"))

        message_dir = os.path.dirname(path)

        playback_path, playback_mime = get_browser_playback_file(
            path,
            message_dir
        )

        return send_file(
            playback_path,
            mimetype=playback_mime,
            as_attachment=False,
            conditional=True
        )

    except Exception as exc:

        flash(
            f"Recovered audio preview error: {str(exc)}"
        )

        return redirect(url_for("inbox_page"))


# --------------------------------------------------
# DOWNLOAD RECEIVED FILE
# --------------------------------------------------

@app.route("/download_final/<msg_id>")
def download_final(msg_id):

    if "username" not in session:
        return redirect(url_for("login"))

    inbox = messaging.list_inbox(
        session["username"]
    )

    meta = next(
        (
            item for item in inbox
            if item.get("msg_id") == msg_id
        ),
        None
    )

    if not meta:

        flash("Message not found.")

        return redirect(url_for("inbox_page"))

    try:

        path = messaging.get_final_path(
            session["username"],
            msg_id,
            meta["final_filename"]
        )

        if not os.path.isfile(path):

            flash("Received file not found.")

            return redirect(url_for("inbox_page"))

        return send_file(
            path,
            as_attachment=True
        )

    except Exception as exc:

        flash(f"Download error: {str(exc)}")

        return redirect(url_for("inbox_page"))


# --------------------------------------------------
# DOWNLOAD RECOVERED SECRET FILE
# --------------------------------------------------

@app.route(
    "/download_recovered/<msg_id>/<path:filename>"
)
def download_recovered(msg_id, filename):

    if "username" not in session:
        return redirect(url_for("login"))

    try:

        inbox = messaging.list_inbox(
            session["username"]
        )

        meta = next(
            (
                item for item in inbox
                if item.get("msg_id") == msg_id
            ),
            None
        )

        if not meta:

            flash("Message not found.")

            return redirect(url_for("inbox_page"))

        safe_filename = secure_filename(filename)

        if not safe_filename or safe_filename != filename:

            flash("Invalid filename.")

            return redirect(url_for("inbox_page"))

        path = messaging.get_final_path(
            session["username"],
            msg_id,
            safe_filename
        )

        if not os.path.isfile(path):

            flash(
                "Recovered file not found. "
                "Please decode the message first."
            )

            return redirect(url_for("inbox_page"))

        return send_file(
            path,
            as_attachment=True
        )

    except Exception as exc:

        flash(f"Download error: {str(exc)}")

        return redirect(url_for("inbox_page"))


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000,
        use_reloader=False
    )
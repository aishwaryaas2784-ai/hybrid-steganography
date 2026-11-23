"""
hybrid_pipeline.py

Hybrid steganography pipeline supporting:
1. Image-only carrier (LSB / DWT)
2. Audio-only carrier (WAV)
3. Image + audio hybrid carrier

The original hide_message() and extract_message() interfaces
remain compatible with older calls.
"""

import os
import uuid

from encrypt import encrypt, decrypt
from image_stego import encode_image, decode_image
from audio_stego import encode_audio, decode_audio
from dwt_stego import encode_image_dwt, decode_image_dwt


def _validate_file(path, description):
    if not path:
        raise ValueError(f"{description} was not provided.")

    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"{description} does not exist: {path}"
        )


def hide_message(
    secret_message: str,
    password: str,
    cover_image_path: str = None,
    cover_audio_path: str = None,
    output_dir: str = "output",
    embedding_method: str = "lsb",
    carrier_type: str = None
):
    """
    Encrypt and hide a secret message using an image, audio,
    or image + audio carrier.

    carrier_type:
        image
        audio
        hybrid

    If carrier_type is omitted, it is detected from the supplied
    cover paths.
    """

    if not isinstance(secret_message, str) or not secret_message:
        raise ValueError("Secret message cannot be empty.")

    if not password:
        raise ValueError("Encryption password cannot be empty.")

    embedding_method = embedding_method.lower().strip()

    if embedding_method not in ("lsb", "dwt"):
        raise ValueError("Embedding method must be 'lsb' or 'dwt'.")

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
        raise ValueError("Carrier type must be image, audio, or hybrid.")

    if carrier_type in ("image", "hybrid"):
        _validate_file(cover_image_path, "Cover image")

    if carrier_type in ("audio", "hybrid"):
        _validate_file(cover_audio_path, "Cover audio")

        if os.path.splitext(cover_audio_path)[1].lower() != ".wav":
            raise ValueError(
                "Audio cover must be WAV. Convert other audio formats "
                "to WAV before using them as a carrier."
            )

    os.makedirs(output_dir, exist_ok=True)

    job_id = uuid.uuid4().hex

    stego_image_path = os.path.join(
        output_dir, f"stego_{job_id}.png"
    )
    stego_audio_path = os.path.join(
        output_dir, f"stego_audio_{job_id}.wav"
    )

    encrypted_text = encrypt(secret_message, password)

    used_audio_layer = False
    bits_used = 0
    final_path = None

    # IMAGE-ONLY OR HYBRID: first create the stego image.
    if carrier_type in ("image", "hybrid"):

        if embedding_method == "dwt":
            encode_image_dwt(
                cover_image_path,
                encrypted_text,
                stego_image_path
            )
        else:
            encode_image(
                cover_image_path,
                encrypted_text,
                stego_image_path,
                password
            )

        _validate_file(stego_image_path, "Stego image")

        final_path = stego_image_path

    # AUDIO-ONLY: embed the encrypted text directly as bytes in WAV.
    if carrier_type == "audio":

        payload_path = os.path.join(
            output_dir, f"audio_payload_{job_id}.bin"
        )

        try:
            with open(payload_path, "wb") as destination:
                destination.write(encrypted_text.encode("utf-8"))

            audio_result = encode_audio(
                cover_audio_path,
                payload_path,
                stego_audio_path
            )

            if isinstance(audio_result, tuple):
                if audio_result[0]:
                    stego_audio_path = audio_result[0]
                if len(audio_result) > 1:
                    bits_used = audio_result[1]
            elif isinstance(audio_result, str):
                stego_audio_path = audio_result

            _validate_file(stego_audio_path, "Stego audio")
            final_path = stego_audio_path
            used_audio_layer = True

        finally:
            if os.path.isfile(payload_path):
                os.remove(payload_path)

    # HYBRID: embed the completed stego image into the WAV carrier.
    elif carrier_type == "hybrid":

        audio_result = encode_audio(
            cover_audio_path,
            stego_image_path,
            stego_audio_path
        )

        if isinstance(audio_result, tuple):
            if audio_result[0]:
                stego_audio_path = audio_result[0]
            if len(audio_result) > 1:
                bits_used = audio_result[1]
        elif isinstance(audio_result, str):
            stego_audio_path = audio_result

        _validate_file(stego_audio_path, "Stego audio")

        final_path = stego_audio_path
        used_audio_layer = True

    _validate_file(final_path, "Final stego carrier")

    return {
        "final_path": final_path,
        "stego_image_path": (
            stego_image_path
            if os.path.isfile(stego_image_path)
            else None
        ),
        "used_audio_layer": used_audio_layer,
        "encrypted_text": encrypted_text,
        "binary_code": None,
        "embedding_method": embedding_method,
        "bits_used": bits_used,
        "carrier_type": carrier_type
    }


def extract_message(
    final_path: str,
    password: str,
    used_audio_layer: bool = False,
    output_dir: str = "output",
    embedding_method: str = "lsb",
    carrier_type: str = None
) -> str:
    """
    Extract and decrypt a message from image, audio, or hybrid carrier.

    Older messages without carrier_type are interpreted using
    used_audio_layer: True means hybrid; False means image.
    """

    _validate_file(final_path, "Stego carrier")

    if not password:
        raise ValueError("Decryption password cannot be empty.")

    embedding_method = embedding_method.lower().strip()

    if embedding_method not in ("lsb", "dwt"):
        raise ValueError("Embedding method must be 'lsb' or 'dwt'.")

    if carrier_type:
        carrier_type = carrier_type.lower().strip()
    else:
        carrier_type = "hybrid" if used_audio_layer else "image"

    if carrier_type not in ("image", "audio", "hybrid"):
        raise ValueError("Unsupported carrier type.")

    os.makedirs(output_dir, exist_ok=True)

    # AUDIO-ONLY: recover the encrypted text bytes directly.
    if carrier_type == "audio":

        extracted_payload_path = os.path.join(
            output_dir,
            f"extracted_audio_payload_{uuid.uuid4().hex}.bin"
        )

        try:
            result = decode_audio(
                final_path,
                extracted_payload_path
            )

            if isinstance(result, str) and os.path.isfile(result):
                extracted_payload_path = result

            _validate_file(
                extracted_payload_path,
                "Extracted audio payload"
            )

            with open(extracted_payload_path, "rb") as source:
                encrypted_text = source.read().decode("utf-8")

        finally:
            if os.path.isfile(extracted_payload_path):
                os.remove(extracted_payload_path)

    else:

        # HYBRID: recover the image from audio first.
        if carrier_type == "hybrid":

            extracted_image_path = os.path.join(
                output_dir,
                f"extracted_{uuid.uuid4().hex}.png"
            )

            result = decode_audio(
                final_path,
                extracted_image_path
            )

            if isinstance(result, str) and os.path.isfile(result):
                extracted_image_path = result

            _validate_file(extracted_image_path, "Extracted image")
            image_path = extracted_image_path

        else:
            image_path = final_path

        # Extract the encrypted message from the image.
        if embedding_method == "dwt":
            encrypted_text = decode_image_dwt(image_path)
        else:
            encrypted_text = decode_image(image_path, password)

    if not encrypted_text:
        raise ValueError("No hidden message was found in the carrier.")

    return decrypt(encrypted_text, password)


if __name__ == "__main__":
    print("Hybrid image/audio steganography pipeline loaded.")
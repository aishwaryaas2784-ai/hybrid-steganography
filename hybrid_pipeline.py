"""
hybrid_pipeline.py
End-to-end hybrid steganography pipeline. Supports two embedding methods:
'lsb' (chaotic-map spatial domain) and 'dwt' (transform domain).
Cover audio is optional.
"""

import os
from encrypt import encrypt, decrypt
from image_stego import encode_image, decode_image, message_to_binary
from audio_stego import encode_audio, decode_audio
from dwt_stego import encode_image_dwt, decode_image_dwt


def hide_message(secret_message: str, password: str, cover_image_path: str,
                  cover_audio_path: str = None, output_dir: str = "output",
                  embedding_method: str = "lsb"):
    os.makedirs(output_dir, exist_ok=True)

    print("Step A: Encrypting secret data...")
    encrypted_text = encrypt(secret_message, password)
    binary_code = message_to_binary(encrypted_text)

    if embedding_method == "dwt":
        print("Step B: Embedding into cover image (DWT transform-domain)...")
        stego_image_path = encode_image_dwt(
            cover_image_path, encrypted_text, os.path.join(output_dir, "stego.png")
        )
    else:
        print("Step B: Embedding into cover image (chaotic-map LSB)...")
        stego_image_path = encode_image(
            cover_image_path, encrypted_text, os.path.join(output_dir, "stego.png"), password
        )

    if cover_audio_path:
        print("Step C: Embedding stego-image into cover audio (hybrid layer)...")
        stego_audio_path, bits_used = encode_audio(
            cover_audio_path, stego_image_path, os.path.join(output_dir, "stego_audio.wav")
        )
        final_path = stego_audio_path
        used_audio_layer = True
    else:
        print("Step C skipped: no cover audio provided, image-only mode.")
        final_path = stego_image_path
        used_audio_layer = False

    print(f"\n✅ Hiding complete. Deliverable: {final_path}")
    return {
        "final_path": final_path,
        "stego_image_path": stego_image_path,
        "used_audio_layer": used_audio_layer,
        "encrypted_text": encrypted_text,
        "binary_code": binary_code,
        "embedding_method": embedding_method
    }


def extract_message(final_path: str, password: str, used_audio_layer: bool,
                     output_dir: str = "output", embedding_method: str = "lsb") -> str:
    os.makedirs(output_dir, exist_ok=True)

    if used_audio_layer:
        print("Step A: Extracting stego-image from audio...")
        image_path = decode_audio(final_path, os.path.join(output_dir, "extracted_stego.png"))
    else:
        print("Step A skipped: image-only mode.")
        image_path = final_path

    if embedding_method == "dwt":
        print("Step B: Extracting encrypted data from stego-image (DWT)...")
        encrypted_text = decode_image_dwt(image_path)
    else:
        print("Step B: Extracting encrypted data from stego-image (chaotic-map LSB)...")
        encrypted_text = decode_image(image_path, password)

    print("Step C: Decrypting...")
    original_message = decrypt(encrypted_text, password)

    print(f"\n✅ Extraction complete.")
    return original_message


if __name__ == "__main__":
    secret = "Confidential: hybrid audio-image steganography, final year 2026 project."
    password = "MySecureKey2026"

    result = hide_message(secret, password, "uploads/cover.png", embedding_method="lsb")
    recovered = extract_message(result["final_path"], password, result["used_audio_layer"],
                                 embedding_method="lsb")
    assert recovered == secret
    print("\n🎉 LSB pipeline test passed.")

    result_dwt = hide_message(secret, password, "uploads/cover.png", embedding_method="dwt")
    recovered_dwt = extract_message(result_dwt["final_path"], password, result_dwt["used_audio_layer"],
                                     embedding_method="dwt")
    assert recovered_dwt == secret
    print("\n🎉 DWT pipeline test passed.")
"""
audio_stego.py
Embeds an entire file (the stego-image) into a WAV audio file using
LSB substitution on the audio sample bytes.
"""

import wave
import os


DELIMITER = "1111111111111110"  # same EOF marker style as image_stego.py


def file_to_binary(file_path: str) -> str:
    """Read any file's raw bytes and convert to a binary string."""
    with open(file_path, "rb") as f:
        data = f.read()
    return ''.join(format(byte, '08b') for byte in data)


def binary_to_file(binary: str, output_path: str):
    """Convert a binary string back into raw bytes and save as a file."""
    byte_chunks = [binary[i:i+8] for i in range(0, len(binary), 8)]
    byte_data = bytes(int(b, 2) for b in byte_chunks if len(b) == 8)
    with open(output_path, "wb") as f:
        f.write(byte_data)


def encode_audio(cover_audio_path: str, secret_file_path: str, output_path: str = "output/stego_audio.wav"):
    """
    Embeds secret_file_path (the stego-image) into cover_audio_path
    using LSB substitution on the audio frame bytes.
    """
    audio = wave.open(cover_audio_path, mode="rb")
    frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))

    binary_message = file_to_binary(secret_file_path) + DELIMITER
    total_bits = len(binary_message)

    max_capacity = len(frame_bytes)
    if total_bits > max_capacity:
        raise ValueError(
            f"Secret file too large for this audio file. "
            f"Capacity: {max_capacity} bits, needed: {total_bits} bits. "
            f"Use a longer audio file or a smaller/more compressed cover image."
        )

    for i in range(total_bits):
        frame_bytes[i] = (frame_bytes[i] & 254) | int(binary_message[i])

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    stego_audio = wave.open(output_path, "wb")
    stego_audio.setparams(audio.getparams())
    stego_audio.writeframes(bytes(frame_bytes))
    stego_audio.close()
    audio.close()

    print(f"✅ Audio encoding complete. Bits embedded: {total_bits}")
    print(f"Stego-audio saved to: {output_path}")
    return output_path, total_bits


def decode_audio(stego_audio_path: str, output_file_path: str = "output/extracted_stego.png"):
    """
    Extracts the hidden file from a stego audio file.
    """
    audio = wave.open(stego_audio_path, mode="rb")
    frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))
    audio.close()

    binary_data = ""
    for byte in frame_bytes:
        binary_data += str(byte & 1)
        if binary_data.endswith(DELIMITER):
            binary_data = binary_data[:-len(DELIMITER)]
            break

    binary_to_file(binary_data, output_file_path)
    print(f"✅ Extraction complete. File recovered to: {output_file_path}")
    return output_file_path


# Quick self-test
if __name__ == "__main__":
    os.makedirs("output", exist_ok=True)

    # Uses the stego.png produced by image_stego.py in Step 3
    stego_image_path = "output/stego.png"
    cover_audio_path = "uploads/cover.wav"

    if not os.path.exists(stego_image_path):
        print("⚠️ Run image_stego.py first to generate output/stego.png")
    else:
        stego_audio_path, bits = encode_audio(cover_audio_path, stego_image_path, "output/stego_audio.wav")

        extracted_path = decode_audio(stego_audio_path, "output/extracted_stego.png")

        # Verify byte-for-byte match
        with open(stego_image_path, "rb") as f1, open(extracted_path, "rb") as f2:
            original_bytes = f1.read()
            extracted_bytes = f2.read()

        assert original_bytes == extracted_bytes, "Mismatch! Extracted file doesn't match original."
        print("\n✅ Audio steganography test passed — extracted file is byte-identical to original.")
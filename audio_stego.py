
"""
audio_stego.py

Binary file steganography in WAV audio using LSB substitution.

Features:
- Embeds arbitrary binary files directly into WAV audio.
- Stores payload length and SHA-256 checksum.
- Checks carrier capacity before embedding.
- Processes audio in chunks to reduce memory usage.
- Extracts files without loading the entire audio into memory.
- Retains support for the previous delimiter-based audio format.

Note:
- Supports uncompressed PCM WAV files.
- Each audio byte carries one hidden bit.
"""

import os
import wave
import struct
import hashlib
import tempfile


MAGIC = b"HYBAUD02"
HEADER_SIZE = 8 + 8 + 32
CHUNK_SIZE = 1024 * 1024

# Original format delimiter, retained for old messages.
DELIMITER = "1111111111111110"


def _ensure_parent(path):
    """Create the output directory if required."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)


def _sha256_file(path):
    """Calculate a file's SHA-256 checksum using chunks."""
    digest = hashlib.sha256()

    with open(path, "rb") as file:
        while True:
            chunk = file.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)

    return digest.digest()


def _iter_file_bits(path):
    """Yield file bits in most-significant-bit-first order."""
    with open(path, "rb") as file:
        while True:
            chunk = file.read(CHUNK_SIZE)
            if not chunk:
                break

            for byte in chunk:
                for shift in range(7, -1, -1):
                    yield (byte >> shift) & 1


def _iter_bytes_bits(data):
    """Yield bits from bytes in most-significant-bit-first order."""
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def _iter_lsb_bytes(audio_path):
    """
    Read audio bytes in chunks and reconstruct groups of eight
    hidden LSBs as bytes.
    """
    with wave.open(audio_path, "rb") as audio:
        params = audio.getparams()

        if params.comptype != "NONE":
            raise ValueError("Only uncompressed PCM WAV files are supported.")

        remaining_frames = params.nframes
        frames_per_chunk = max(
            1, CHUNK_SIZE // (params.nchannels * params.sampwidth)
        )

        current_byte = 0
        bit_count = 0

        while remaining_frames > 0:
            frame_count = min(remaining_frames, frames_per_chunk)
            chunk = audio.readframes(frame_count)

            if not chunk:
                break

            remaining_frames -= frame_count

            for value in chunk:
                current_byte = (current_byte << 1) | (value & 1)
                bit_count += 1

                if bit_count == 8:
                    yield current_byte
                    current_byte = 0
                    bit_count = 0


def _read_exact_bytes(byte_iterator, count):
    """Read an exact number of reconstructed hidden bytes."""
    result = bytearray()

    for _ in range(count):
        try:
            result.append(next(byte_iterator))
        except StopIteration:
            raise ValueError("Audio ended before the hidden data was complete.")

    return bytes(result)


def file_to_binary(file_path: str) -> str:
    """Legacy helper: convert a complete file into a binary string."""
    with open(file_path, "rb") as file:
        data = file.read()

    return "".join(format(byte, "08b") for byte in data)


def binary_to_file(binary: str, output_path: str):
    """Legacy helper: convert a binary string back into a file."""
    if len(binary) % 8 != 0:
        binary = binary[:len(binary) - (len(binary) % 8)]

    _ensure_parent(output_path)

    with open(output_path, "wb") as file:
        for index in range(0, len(binary), 8):
            file.write(bytes([int(binary[index:index + 8], 2)]))


def encode_audio(
    cover_audio_path: str,
    secret_file_path: str,
    output_path: str = "output/stego_audio.wav"
):
    """
    Embed a binary file into a PCM WAV carrier.

    New format:
        MAGIC (8 bytes)
        Payload length (8 bytes)
        SHA-256 checksum (32 bytes)
        Original file bytes

    One audio byte stores one payload bit.
    """

    if not os.path.isfile(cover_audio_path):
        raise FileNotFoundError(
            f"Cover audio not found: {cover_audio_path}"
        )

    if not os.path.isfile(secret_file_path):
        raise FileNotFoundError(
            f"Secret file not found: {secret_file_path}"
        )

    if os.path.abspath(cover_audio_path) == os.path.abspath(output_path):
        raise ValueError("Output path must be different from the cover audio.")

    payload_size = os.path.getsize(secret_file_path)
    checksum = _sha256_file(secret_file_path)

    header = (
        MAGIC
        + struct.pack(">Q", payload_size)
        + checksum
    )

    total_bits = (len(header) + payload_size) * 8

    _ensure_parent(output_path)

    temporary_path = output_path + ".tmp"

    try:
        with wave.open(cover_audio_path, "rb") as source:
            params = source.getparams()

            if params.comptype != "NONE":
                raise ValueError(
                    "Only uncompressed PCM WAV files are supported."
                )

            if params.sampwidth not in (1, 2, 3, 4):
                raise ValueError("Unsupported WAV sample width.")

            capacity_bits = (
                params.nframes * params.nchannels * params.sampwidth
            )

            if total_bits > capacity_bits:
                raise ValueError(
                    "Secret file is too large for this WAV carrier. "
                    f"Capacity: {capacity_bits} bits; "
                    f"required: {total_bits} bits."
                )

            bit_stream = iter(
                list(_iter_bytes_bits(header))
            )

            def payload_bits():
                for bit in _iter_file_bits(secret_file_path):
                    yield bit

            # Chain header and file bits without converting the file
            # into a large binary string.
            import itertools

            bit_stream = itertools.chain(
                _iter_bytes_bits(header),
                payload_bits()
            )

            bits_written = 0

            with wave.open(temporary_path, "wb") as destination:
                destination.setparams(params)

                frames_per_chunk = max(
                    1,
                    CHUNK_SIZE // (
                        params.nchannels * params.sampwidth
                    )
                )

                remaining_frames = params.nframes

                while remaining_frames > 0:
                    frame_count = min(
                        remaining_frames, frames_per_chunk
                    )

                    chunk = bytearray(source.readframes(frame_count))

                    if not chunk:
                        break

                    remaining_frames -= frame_count

                    for index in range(len(chunk)):
                        if bits_written >= total_bits:
                            break

                        bit = next(bit_stream)
                        chunk[index] = (chunk[index] & 0xFE) | bit
                        bits_written += 1

                    destination.writeframesraw(bytes(chunk))

        if bits_written != total_bits:
            raise ValueError("Audio embedding did not complete successfully.")

        os.replace(temporary_path, output_path)

    except Exception:
        if os.path.exists(temporary_path):
            os.remove(temporary_path)
        raise

    print("Audio encoding complete.")
    print(f"Bits embedded: {total_bits}")
    print(f"Stego-audio saved to: {output_path}")

    return output_path, total_bits


def _decode_new_format(byte_iterator, output_file_path):
    """Decode the new length-prefixed, checksum-protected format."""

    payload_length = struct.unpack(
        ">Q", _read_exact_bytes(byte_iterator, 8)
    )[0]

    expected_checksum = _read_exact_bytes(byte_iterator, 32)

    _ensure_parent(output_file_path)

    digest = hashlib.sha256()
    remaining = payload_length

    with open(output_file_path, "wb") as output:
        while remaining > 0:
            count = min(CHUNK_SIZE, remaining)
            chunk = _read_exact_bytes(byte_iterator, count)

            output.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)

    if digest.digest() != expected_checksum:
        os.remove(output_file_path)
        raise ValueError(
            "Extracted file checksum does not match. "
            "The audio may have been modified or corrupted."
        )

    return output_file_path


def _decode_legacy_format(stego_audio_path, output_file_path):
    """
    Decode the original delimiter-based format.

    The original format stored the secret file bits followed by
    DELIMITER. This function is retained for old messages.
    """

    delimiter = int(DELIMITER, 2)
    rolling = 0
    rolling_count = 0

    output_buffer = bytearray()
    current_byte = 0
    bit_count = 0

    _ensure_parent(output_file_path)

    with open(output_file_path, "wb") as output:
        for hidden_byte in _iter_lsb_bytes(stego_audio_path):
            # This iterator returns complete groups of eight bits.
            # Process each bit to detect the old delimiter.
            for shift in range(7, -1, -1):
                bit = (hidden_byte >> shift) & 1

                rolling = ((rolling << 1) | bit) & 0xFFFF
                rolling_count += 1

                if rolling_count >= 16 and rolling == delimiter:
                    output.write(output_buffer)
                    return output_file_path

                current_byte = (current_byte << 1) | bit
                bit_count += 1

                if bit_count == 8:
                    output_buffer.append(current_byte)
                    current_byte = 0
                    bit_count = 0

                    if len(output_buffer) >= CHUNK_SIZE:
                        output.write(output_buffer)
                        output_buffer.clear()

        raise ValueError(
            "Legacy audio delimiter not found. "
            "The hidden file may be incomplete or corrupted."
        )


def decode_audio(
    stego_audio_path: str,
    output_file_path: str = "output/extracted_stego.png"
):
    """
    Extract a hidden file from a WAV audio file.

    Detects the new format automatically and falls back to the
    previous delimiter-based format for older messages.
    """

    if not os.path.isfile(stego_audio_path):
        raise FileNotFoundError(
            f"Stego audio not found: {stego_audio_path}"
        )

    iterator = _iter_lsb_bytes(stego_audio_path)

    try:
        magic = _read_exact_bytes(iterator, len(MAGIC))
    except ValueError:
        raise ValueError("Audio does not contain a valid hidden file.")

    if magic == MAGIC:
        # Continue reading from the same iterator after the magic.
        result = _decode_new_format(iterator, output_file_path)
    else:
        # Old format: scan the original audio LSB stream.
        result = _decode_legacy_format(
            stego_audio_path, output_file_path
        )

    print("Audio extraction complete.")
    print(f"Recovered file: {result}")

    return result


if __name__ == "__main__":
    os.makedirs("output", exist_ok=True)

    cover_audio_path = "uploads/cover.wav"
    secret_file_path = "output/stego.png"

    if not os.path.exists(cover_audio_path):
        print("Cover audio not found:", cover_audio_path)

    elif not os.path.exists(secret_file_path):
        print("Secret file not found:", secret_file_path)

    else:
        encoded_path, bits = encode_audio(
            cover_audio_path,
            secret_file_path,
            "output/stego_audio.wav"
        )

        extracted_path = decode_audio(
            encoded_path,
            "output/extracted_stego.png"
        )

        with open(secret_file_path, "rb") as original:
            original_data = original.read()

        with open(extracted_path, "rb") as recovered:
            recovered_data = recovered.read()

        assert original_data == recovered_data

        print("Audio steganography test passed.")
        print("Original and extracted files are identical.")

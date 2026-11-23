
"""
image_stego.py

Image steganography using password-dependent RGB LSB substitution.

Features:
- Embeds text and binary-compatible UTF-8 payloads.
- Stores payload length and SHA-256 checksum.
- Checks image capacity before embedding.
- Uses a password-dependent pixel/channel traversal.
- Avoids constructing a huge binary string for the payload.
- Preserves the function names used by hybrid_pipeline.py.
"""

import os
import hashlib
import math
import struct

from PIL import Image


MAGIC = b"HYBIMG02"
HEADER_SIZE = 8 + 8 + 32


def message_to_binary(message: str) -> str:
    """Convert a string into a binary string."""
    return "".join(format(byte, "08b") for byte in message.encode("utf-8"))


def binary_to_message(binary: str) -> str:
    """Convert a binary string into UTF-8 text."""
    if len(binary) % 8 != 0:
        raise ValueError("Binary data length must be divisible by 8.")

    data = bytes(
        int(binary[index:index + 8], 2)
        for index in range(0, len(binary), 8)
    )

    return data.decode("utf-8")


def _password_values(password: str, total_slots: int):
    """
    Create a deterministic, password-dependent traversal of all
    available RGB channel slots.

    The affine traversal visits every slot exactly once without
    storing a large shuffled list in memory.
    """
    if not password:
        raise ValueError("A password is required for image steganography.")

    if total_slots <= 0:
        raise ValueError("Image has no available RGB channel slots.")

    digest = hashlib.sha256(password.encode("utf-8")).digest()

    start = int.from_bytes(digest[:8], "big") % total_slots
    step = int.from_bytes(digest[8:16], "big") % total_slots

    if step == 0:
        step = 1

    while math.gcd(step, total_slots) != 1:
        step += 1
        if step >= total_slots:
            step = 1

    return start, step


def get_embedding_order(width: int, height: int, password: str):
    """
    Return a password-dependent pixel order.

    This function is retained for compatibility with code that
    imports get_embedding_order().
    """
    total_pixels = width * height
    start, step = _password_values(password, total_pixels)

    order = []
    position = start

    for _ in range(total_pixels):
        y, x = divmod(position, width)
        order.append((x, y))
        position = (position + step) % total_pixels

    return order


def _iter_bits(data: bytes):
    """Yield bits from bytes, most-significant bit first."""
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def _read_bytes(bit_iterator, count: int) -> bytes:
    """Read a specified number of bytes from a bit iterator."""
    result = bytearray()

    for _ in range(count):
        value = 0

        for _ in range(8):
            try:
                bit = next(bit_iterator)
            except StopIteration:
                raise ValueError(
                    "Image ended before the hidden message was complete."
                )

            value = (value << 1) | bit

        result.append(value)

    return bytes(result)


def _image_bit_iterator(image, password: str):
    """Yield image RGB LSBs in the password-dependent order."""
    width, height = image.size
    total_slots = width * height * 3

    start, step = _password_values(password, total_slots)
    pixels = image.load()

    position = start

    for _ in range(total_slots):
        pixel_index, channel_index = divmod(position, 3)
        y, x = divmod(pixel_index, width)

        pixel = pixels[x, y]
        yield pixel[channel_index] & 1

        position = (position + step) % total_slots


def _embed_bits(image, password: str, data: bytes):
    """Embed bytes into an RGB image."""
    width, height = image.size
    total_slots = width * height * 3
    required_bits = len(data) * 8

    if required_bits > total_slots:
        raise ValueError(
            "Secret message is too large for this image. "
            f"Capacity: {total_slots} bits; "
            f"required: {required_bits} bits."
        )

    start, step = _password_values(password, total_slots)
    pixels = image.load()

    position = start
    bits_written = 0

    for bit in _iter_bits(data):
        pixel_index, channel_index = divmod(position, 3)
        y, x = divmod(pixel_index, width)

        pixel = list(pixels[x, y])
        pixel[channel_index] = (
            (pixel[channel_index] & 0xFE) | bit
        )
        pixels[x, y] = tuple(pixel)

        position = (position + step) % total_slots
        bits_written += 1

    return bits_written


def encode_image(
    cover_path: str,
    secret_message: str,
    output_path: str = "output/stego.png",
    password: str = ""
):
    """
    Hide a text message inside an image using RGB LSB substitution.

    The hidden data format is:
        MAGIC (8 bytes)
        Payload length (8 bytes)
        SHA-256 checksum (32 bytes)
        UTF-8 message bytes
    """

    if not os.path.isfile(cover_path):
        raise FileNotFoundError(
            f"Cover image not found: {cover_path}"
        )

    if not password:
        raise ValueError("A password is required.")

    if os.path.abspath(cover_path) == os.path.abspath(output_path):
        raise ValueError("Output path must differ from the cover image.")

    payload = secret_message.encode("utf-8")
    checksum = hashlib.sha256(payload).digest()

    header = (
        MAGIC
        + struct.pack(">Q", len(payload))
        + checksum
    )

    complete_data = header + payload

    os.makedirs(
        os.path.dirname(os.path.abspath(output_path)),
        exist_ok=True
    )

    with Image.open(cover_path) as source:
        image = source.convert("RGB")

    capacity_bits = image.width * image.height * 3
    required_bits = len(complete_data) * 8

    if required_bits > capacity_bits:
        raise ValueError(
            "Secret message is too large for this image. "
            f"Capacity: {capacity_bits} bits; "
            f"required: {required_bits} bits."
        )

    _embed_bits(image, password, complete_data)

    # PNG is lossless and is required to preserve the hidden LSBs.
    image.save(output_path, format="PNG")

    print("Image encoding complete.")
    print(f"Payload size: {len(payload)} bytes")
    print(f"Bits embedded: {required_bits}")
    print(f"Stego image saved to: {output_path}")

    return output_path


def decode_image(stego_path: str, password: str):
    """
    Extract and verify a hidden UTF-8 message from a stego image.
    """

    if not os.path.isfile(stego_path):
        raise FileNotFoundError(
            f"Stego image not found: {stego_path}"
        )

    if not password:
        raise ValueError("A password is required.")

    with Image.open(stego_path) as source:
        image = source.convert("RGB")

    bit_iterator = _image_bit_iterator(image, password)

    magic = _read_bytes(bit_iterator, len(MAGIC))

    if magic != MAGIC:
        raise ValueError(
            "No valid message found. Check the password and image. "
            "This decoder expects the new HYBIMG02 image format."
        )

    payload_length = struct.unpack(
        ">Q", _read_bytes(bit_iterator, 8)
    )[0]

    expected_checksum = _read_bytes(bit_iterator, 32)

    capacity_bytes = (image.width * image.height * 3) // 8
    if HEADER_SIZE + payload_length > capacity_bytes:
        raise ValueError("Invalid payload length in the image.")

    payload = _read_bytes(bit_iterator, payload_length)

    actual_checksum = hashlib.sha256(payload).digest()

    if actual_checksum != expected_checksum:
        raise ValueError(
            "Message verification failed. The password may be "
            "incorrect or the image may have been modified."
        )

    try:
        message = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Recovered message is not valid UTF-8 text.")

    print("Image extraction complete.")
    print(f"Recovered payload size: {payload_length} bytes")

    return message


if __name__ == "__main__":
    import sys

    os.makedirs("output", exist_ok=True)

    if len(sys.argv) < 4:
        print(
            "Usage:\n"
            "  python image_stego.py <cover_image> "
            "<message> <password>"
        )
    else:
        cover = sys.argv[1]
        message = sys.argv[2]
        password = sys.argv[3]

        stego_path = encode_image(
            cover,
            message,
            "output/stego.png",
            password
        )

        recovered = decode_image(stego_path, password)

        assert recovered == message

        print("Image steganography test passed.")

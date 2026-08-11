"""
dwt_stego.py
DWT (Discrete Wavelet Transform) based image steganography -- an
alternative, frequency-domain embedding method compared against the
LSB spatial-domain approach in image_stego.py.
"""

import numpy as np
import pywt
from PIL import Image

DELIMITER = "1111111111111110"


def message_to_binary(message: str) -> str:
    return ''.join(format(ord(char), '08b') for char in message)


def binary_to_message(binary: str) -> str:
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return ''.join(chr(int(c, 2)) for c in chars if len(c) == 8)


def encode_image_dwt(cover_path: str, secret_message: str, output_path: str):
    img = Image.open(cover_path).convert("RGB")
    img_array = np.array(img).astype(np.float64)

    blue_channel = img_array[:, :, 2]

    coeffs = pywt.dwt2(blue_channel, 'haar')
    cA, (cH, cV, cD) = coeffs

    binary_message = message_to_binary(secret_message) + DELIMITER
    total_bits = len(binary_message)

    flat_cH = cH.flatten()
    max_capacity = len(flat_cH)
    if total_bits > max_capacity:
        raise ValueError(
            f"Message too large for DWT capacity. Capacity: {max_capacity} bits, needed: {total_bits} bits. "
            f"DWT capacity is lower than LSB -- use a larger image or shorter message."
        )

    quant_step = 4.0
    for i in range(total_bits):
        coeff = flat_cH[i]
        bit = int(binary_message[i])
        quotient = round(coeff / quant_step)
        if quotient % 2 != bit:
            quotient += 1 if coeff >= 0 else -1
        flat_cH[i] = quotient * quant_step

    cH_modified = flat_cH.reshape(cH.shape)

    modified_blue = pywt.idwt2((cA, (cH_modified, cV, cD)), 'haar')
    modified_blue = modified_blue[:blue_channel.shape[0], :blue_channel.shape[1]]
    modified_blue = np.clip(modified_blue, 0, 255)

    img_array[:, :, 2] = modified_blue
    result_img = Image.fromarray(img_array.astype(np.uint8), "RGB")
    result_img.save(output_path)

    print(f"✅ DWT image encoding complete. Bits embedded: {total_bits}")
    return output_path


def decode_image_dwt(stego_path: str) -> str:
    img = Image.open(stego_path).convert("RGB")
    img_array = np.array(img).astype(np.float64)
    blue_channel = img_array[:, :, 2]

    coeffs = pywt.dwt2(blue_channel, 'haar')
    cA, (cH, cV, cD) = coeffs
    flat_cH = cH.flatten()

    quant_step = 4.0
    binary_data = ""
    for coeff in flat_cH:
        quotient = round(coeff / quant_step)
        bit = quotient % 2
        binary_data += str(int(bit))
        if binary_data.endswith(DELIMITER):
            binary_data = binary_data[:-len(DELIMITER)]
            return binary_to_message(binary_data)

    return binary_to_message(binary_data)


if __name__ == "__main__":
    import os
    os.makedirs("output", exist_ok=True)
    from encrypt import encrypt, decrypt

    secret = "DWT test message"
    password = "MySecureKey2026"

    encrypted = encrypt(secret, password)
    stego_path = encode_image_dwt("uploads/cover.png", encrypted, "output/stego_dwt.png")

    extracted_encrypted = decode_image_dwt(stego_path)
    decrypted = decrypt(extracted_encrypted, password)

    print("\nOriginal secret:", secret)
    print("Decrypted result:", decrypted)
    assert decrypted == secret, "Mismatch!"
    print("\n✅ DWT steganography test passed.")
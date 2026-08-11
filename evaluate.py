"""
evaluate.py
Quantitative evaluation metrics for the hybrid steganography system:
- PSNR (Peak Signal-to-Noise Ratio) for image quality
- SNR (Signal-to-Noise Ratio) for audio quality
- Embedding capacity
These are the standard metrics expected in steganography research papers
and your project report.
"""

import numpy as np
from PIL import Image
import wave


def calculate_image_psnr(original_path: str, stego_path: str) -> float:
    """
    PSNR between original cover image and stego image.
    Higher PSNR (typically 40+ dB) = less visual distortion = better.
    """
    original = np.array(Image.open(original_path).convert("RGB"), dtype=np.float64)
    stego = np.array(Image.open(stego_path).convert("RGB"), dtype=np.float64)

    if original.shape != stego.shape:
        raise ValueError("Image dimensions don't match -- can't compare.")

    mse = np.mean((original - stego) ** 2)
    if mse == 0:
        return float("inf")  # identical images

    max_pixel = 255.0
    psnr = 20 * np.log10(max_pixel / np.sqrt(mse))
    return round(psnr, 2)


def calculate_audio_snr(original_path: str, stego_path: str) -> float:
    """
    SNR between original cover audio and stego audio.
    Higher SNR (typically 30+ dB) = less audible distortion = better.
    """
    orig_wav = wave.open(original_path, "rb")
    stego_wav = wave.open(stego_path, "rb")

    orig_frames = np.frombuffer(orig_wav.readframes(orig_wav.getnframes()), dtype=np.int16).astype(np.float64)
    stego_frames = np.frombuffer(stego_wav.readframes(stego_wav.getnframes()), dtype=np.int16).astype(np.float64)

    orig_wav.close()
    stego_wav.close()

    min_len = min(len(orig_frames), len(stego_frames))
    orig_frames = orig_frames[:min_len]
    stego_frames = stego_frames[:min_len]

    noise = orig_frames - stego_frames
    signal_power = np.mean(orig_frames ** 2)
    noise_power = np.mean(noise ** 2)

    if noise_power == 0:
        return float("inf")

    snr = 10 * np.log10(signal_power / noise_power)
    return round(snr, 2)


def calculate_capacity(cover_image_path: str) -> dict:
    """
    Maximum embedding capacity of a cover image in bits, bytes, and
    as a percentage relative to total image size on disk.
    """
    img = Image.open(cover_image_path)
    max_bits = img.width * img.height * 3  # 1 bit per RGB channel
    max_bytes = max_bits / 8

    return {
        "width": img.width,
        "height": img.height,
        "max_bits": max_bits,
        "max_bytes": round(max_bytes, 2),
        "max_kb": round(max_bytes / 1024, 2)
    }


def full_evaluation_report(cover_image_path: str, stego_image_path: str,
                            cover_audio_path: str = None, stego_audio_path: str = None) -> dict:
    """
    Runs all applicable metrics and returns a combined results dictionary.
    """
    report = {}

    report["image_psnr_db"] = calculate_image_psnr(cover_image_path, stego_image_path)
    report["image_capacity"] = calculate_capacity(cover_image_path)

    if cover_audio_path and stego_audio_path:
        report["audio_snr_db"] = calculate_audio_snr(cover_audio_path, stego_audio_path)
    else:
        report["audio_snr_db"] = None

    return report


if __name__ == "__main__":
    from hybrid_pipeline import hide_message

    secret = "Confidential evaluation test message for PSNR and SNR metrics."
    password = "MySecureKey2026"

    result = hide_message(secret, password, "uploads/cover.png", "uploads/cover.wav")

    report = full_evaluation_report(
        cover_image_path="uploads/cover.png",
        stego_image_path="output/stego.png",
        cover_audio_path="uploads/cover.wav" if result["used_audio_layer"] else None,
        stego_audio_path=result["final_path"] if result["used_audio_layer"] else None
    )

    print("\n=== EVALUATION REPORT ===")
    print(f"Image PSNR: {report['image_psnr_db']} dB  (higher = better, 40+ dB is excellent)")
    if report["audio_snr_db"] is not None:
        print(f"Audio SNR: {report['audio_snr_db']} dB  (higher = better, 30+ dB is excellent)")
    print(f"Image capacity: {report['image_capacity']['max_kb']} KB "
          f"({report['image_capacity']['max_bits']} bits)")
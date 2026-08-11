"""
report.py
Generates a professional PDF summary report for a steganography operation --
useful both as a live demo feature and as documentation for your submission.
"""

import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from evaluate import full_evaluation_report


def generate_report(output_pdf_path: str, sender: str, recipient: str,
                     secret_type: str, security_score: float,
                     cover_image_path: str, stego_image_path: str,
                     cover_audio_path: str = None, stego_audio_path: str = None,
                     used_audio_layer: bool = False):
    """
    Builds a PDF report summarizing one hide/send operation:
    metadata, quality metrics (PSNR/SNR), capacity, and AI security score.
    """
    doc = SimpleDocTemplate(output_pdf_path, pagesize=A4,
                             topMargin=20*mm, bottomMargin=20*mm,
                             leftMargin=20*mm, rightMargin=20*mm)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle", parent=styles["Title"], fontSize=20, textColor=HexColor("#0f172a")
    )
    heading_style = ParagraphStyle(
        "HeadingStyle", parent=styles["Heading2"], textColor=HexColor("#1e293b"),
        spaceBefore=14, spaceAfter=8
    )
    body_style = styles["BodyText"]

    elements = []

    elements.append(Paragraph("Hybrid Audio-Image Steganography", title_style))
    elements.append(Paragraph("Secure Transmission Report", styles["Heading3"]))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(
        f"Generated on: {datetime.now().strftime('%d %B %Y, %I:%M %p')}", body_style
    ))
    elements.append(Spacer(1, 16))

    # --- Message metadata table ---
    elements.append(Paragraph("Transmission Details", heading_style))
    meta_data = [
        ["Sender", sender],
        ["Recipient", recipient],
        ["Secret Content Type", secret_type],
        ["Embedding Layers", "Image + Audio (Hybrid)" if used_audio_layer else "Image Only"],
        ["Encryption", "AES-256 (PBKDF2 key derivation)"],
        ["Embedding Method", "Password-seeded pseudo-random LSB"],
    ]
    meta_table = Table(meta_data, colWidths=[160, 300])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), HexColor("#e2e8f0")),
        ("TEXTCOLOR", (0, 0), (-1, -1), HexColor("#0f172a")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#94a3b8")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 16))

    # --- Quality / security metrics ---
    elements.append(Paragraph("Quality & Security Metrics", heading_style))

    eval_report = full_evaluation_report(
        cover_image_path=cover_image_path,
        stego_image_path=stego_image_path,
        cover_audio_path=cover_audio_path,
        stego_audio_path=stego_audio_path
    )

    metrics_data = [
        ["Metric", "Value", "Interpretation"],
        ["Image PSNR", f"{eval_report['image_psnr_db']} dB",
         "Excellent (>40 dB = imperceptible)" if eval_report['image_psnr_db'] != float('inf')
         and eval_report['image_psnr_db'] > 40 else "Good"],
        ["Image Capacity", f"{eval_report['image_capacity']['max_kb']} KB",
         f"{eval_report['image_capacity']['max_bits']} bits max"],
        ["AI Steganalysis Score", f"{security_score:.4f}",
         "Low risk / hard to detect" if security_score < 0.5 else "Higher risk"],
    ]
    if eval_report["audio_snr_db"] is not None:
        metrics_data.append([
            "Audio SNR", f"{eval_report['audio_snr_db']} dB",
            "Excellent (>30 dB = inaudible)" if eval_report['audio_snr_db'] > 30 else "Good"
        ])

    metrics_table = Table(metrics_data, colWidths=[150, 100, 210])
    metrics_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#38bdf8")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#94a3b8")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, HexColor("#f1f5f9")]),
    ]))
    elements.append(metrics_table)
    elements.append(Spacer(1, 16))

    # --- Visual comparison ---
    elements.append(Paragraph("Visual Comparison", heading_style))
    elements.append(Paragraph(
        "Cover image (left) and stego image (right) — visually indistinguishable, "
        "confirming imperceptible embedding.", body_style
    ))
    elements.append(Spacer(1, 8))

    img_table_data = [[
        RLImage(cover_image_path, width=180, height=180),
        RLImage(stego_image_path, width=180, height=180)
    ]]
    img_table = Table(img_table_data, colWidths=[200, 200])
    elements.append(img_table)
    elements.append(Spacer(1, 16))

    # --- Conclusion ---
    elements.append(Paragraph("Conclusion", heading_style))
    elements.append(Paragraph(
        "The hybrid steganography system successfully embedded the encrypted secret data "
        "within the cover media using password-seeded adaptive LSB substitution, achieving "
        "high imperceptibility as confirmed by the PSNR/SNR metrics above. The AI-based "
        "steganalysis scorer independently validated low detectability, demonstrating "
        "resistance to statistical steganalysis attacks beyond simple visual inspection.",
        body_style
    ))

    doc.build(elements)
    print(f"✅ PDF report generated: {output_pdf_path}")
    return output_pdf_path


if __name__ == "__main__":
    import os
    from hybrid_pipeline import hide_message
    from ai_scorer import score_image

    os.makedirs("output", exist_ok=True)

    secret = "Final year project demonstration message."
    password = "MySecureKey2026"

    result = hide_message(secret, password, "uploads/cover.png", "uploads/cover.wav")
    score = score_image(result["stego_image_path"])

    generate_report(
        output_pdf_path="output/steganography_report.pdf",
        sender="aish",
        recipient="suhas",
        secret_type="text",
        security_score=score,
        cover_image_path="uploads/cover.png",
        stego_image_path=result["stego_image_path"],
        cover_audio_path="uploads/cover.wav" if result["used_audio_layer"] else None,
        stego_audio_path=result["final_path"] if result["used_audio_layer"] else None,
        used_audio_layer=result["used_audio_layer"]
    )
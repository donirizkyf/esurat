import hashlib
import hmac
import os
from datetime import datetime
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas


def generate_submission_receipt(
    output_path: Path,
    document_id: str,
    username: str,
    bagian: str,
    document_date: str,
    subject: str,
    status: str,
    timestamp: str,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    pdf = canvas.Canvas(str(output_path), pagesize=A4)
    width, height = A4

    pdf.setTitle(f"Tanda Terima {document_id}")

    top = height - 25 * mm
    left = 20 * mm
    line_gap = 10 * mm

    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(left, top, "Tanda Terima Pengajuan Dokumen")

    pdf.setFont("Helvetica", 10)
    pdf.drawString(left, top - 8 * mm, f"Dibuat: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    rows = [
        ("Document ID", document_id),
        ("User Name", username),
        ("Bagian", bagian),
        ("Date", document_date),
        ("Subject", subject),
        ("Status", status),
        ("Timestamp", timestamp),
    ]

    signature_secret = os.getenv("RECEIPT_SIGNATURE_SECRET", "submitdoc-receipt-signature")
    signature_payload = "|".join([document_id, username, bagian, document_date, subject, status, timestamp])
    signature_value = hmac.new(
        signature_secret.encode("utf-8"),
        signature_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest().upper()

    y = top - 22 * mm
    pdf.setFont("Helvetica", 12)
    for label, value in rows:
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(left, y, f"{label}:")
        pdf.setFont("Helvetica", 11)
        pdf.drawString(left + 38 * mm, y, value)
        y -= line_gap

    signature_box_y = y - 4 * mm
    box_width = 78 * mm
    box_height = 28 * mm
    pdf.roundRect(left, signature_box_y - box_height, box_width, box_height, 4 * mm, stroke=1, fill=0)
    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(left + 4 * mm, signature_box_y - 7 * mm, "Digital Signature")
    pdf.setFont("Helvetica", 9)
    pdf.drawString(left + 4 * mm, signature_box_y - 13 * mm, "Signed electronically by Sistem Pengajuan Dokumen")
    pdf.drawString(left + 4 * mm, signature_box_y - 19 * mm, f"Signature ID: {signature_value[:24]}")

    pdf.setFont("Helvetica-Oblique", 10)
    pdf.drawString(left, signature_box_y - box_height - 8 * mm, "Harap simpan tanda terima ini untuk arsip Anda.")

    pdf.showPage()
    pdf.save()

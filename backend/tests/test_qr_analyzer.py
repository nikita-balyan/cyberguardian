import io
import pytest
from fastapi.testclient import TestClient
from PIL import Image
import qrcode
from app.main import app

client = TestClient(app)


def generate_qr_bytes(data: str) -> bytes:
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()


def generate_plain_image_bytes() -> bytes:
    img = Image.new("RGB", (150, 150), color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()


def test_qr_scan_valid_qr_url():
    qr_bytes = generate_qr_bytes("https://example.com")
    response = client.post(
        "/api/v1/scan/qr",
        files={"file": ("valid_qr.png", qr_bytes, "image/png")}
    )
    assert response.status_code == 200
    data = response.json()
    assert "evidence" in data
    assert data["evidence"]["has_qr_code"] is True
    assert data["evidence"]["extracted_text"] == "https://example.com"
    assert data["evidence"]["is_url"] is True
    assert "risk_assessment" in data
    assert "explanation" in data


def test_qr_scan_no_qr_code():
    plain_bytes = generate_plain_image_bytes()
    response = client.post(
        "/api/v1/scan/qr",
        files={"file": ("no_qr.png", plain_bytes, "image/png")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["evidence"]["has_qr_code"] is False
    assert data["evidence"]["extracted_text"] is None
    assert data["risk_assessment"]["level"] == "LOW"


def test_qr_scan_invalid_file_handling():
    corrupted_data = b"This is not a valid image payload"
    response = client.post(
        "/api/v1/scan/qr",
        files={"file": ("corrupted.png", corrupted_data, "image/png")}
    )
    assert response.status_code in [200, 400, 500]
    data = response.json()
    if response.status_code == 200:
        assert data["evidence"]["has_qr_code"] is False
import io
import inspect
import logging
from typing import Optional
from urllib.parse import urlparse
import numpy as np
from PIL import Image
import cv2

from ..models.schemas import QREvidence, URLEvidence
from .url_analyzer import analyze_url

logger = logging.getLogger(__name__)

# Optional pyzbar support
try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    PYZBAR_AVAILABLE = True
except (ImportError, OSError):
    PYZBAR_AVAILABLE = False
    pyzbar_decode = None


def _decode_qr_image(image_bytes: bytes) -> Optional[str]:
    """Decodes QR code text using OpenCV first, falling back to pyzbar."""
    try:
        pil_img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        img_np = np.array(pil_img)
        img_cv = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)

        # 1. Primary: OpenCV QRCodeDetector
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(img_cv)
        if data and data.strip():
            return data.strip()

        # 2. Grayscale fallback with OpenCV
        gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
        data, _, _ = detector.detectAndDecode(gray)
        if data and data.strip():
            return data.strip()

        # 3. Secondary: pyzbar fallback if available
        if PYZBAR_AVAILABLE and pyzbar_decode is not None:
            results = pyzbar_decode(pil_img)
            if results:
                return results[0].data.decode("utf-8", errors="ignore").strip()

    except Exception as e:
        logger.error(f"Error decoding image for QR code: {e}")

    return None


async def analyze_qr_code(image_bytes: bytes) -> QREvidence:
    """
    Accepts uploaded image bytes (PNG, JPEG, WebP),
    decodes any QR code present, extracts payload,
    and runs URL analysis if the payload is a URL.
    """
    extracted_text = _decode_qr_image(image_bytes)

    if not extracted_text:
        return QREvidence(
            has_qr_code=False,
            extracted_text=None,
            is_url=False,
            url_evidence=None,
        )

    # Determine if extracted text is a URL
    is_url = False
    url_evidence: Optional[URLEvidence] = None

    parsed = urlparse(extracted_text)
    if parsed.scheme in ["http", "https"] or (
        not parsed.scheme
        and "." in parsed.path.split("/")[0]
        and len(parsed.path.split("/")[0]) > 3
    ):
        is_url = True
        try:
            url_to_analyze = extracted_text
            if not url_to_analyze.startswith(("http://", "https://")):
                url_to_analyze = "https://" + url_to_analyze
            
            res = analyze_url(url_to_analyze)
            if inspect.isawaitable(res):
                url_evidence = await res
            else:
                url_evidence = res
        except Exception as e:
            logger.error(f"URL analysis failed for QR payload '{extracted_text}': {e}")
            url_evidence = None

    return QREvidence(
        has_qr_code=True,
        extracted_text=extracted_text,
        is_url=is_url,
        url_evidence=url_evidence,
    )
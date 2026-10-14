#config.py
import os

from dotenv import load_dotenv

load_dotenv()


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

APP_ENV = os.getenv("APP_ENV", "development").strip().lower()  # "production" hides /docs

# Comma-separated list of frontend origins allowed to call the API
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
    if o.strip()
]

# Set to true ONLY when the API runs behind a reverse proxy you control (nginx, Render, Fly...)
TRUST_PROXY_HEADERS = _bool("TRUST_PROXY_HEADERS", False)

# Limits per client IP (set a value to 0 to disable that limit)
RATE_LIMIT_SCANS_PER_MIN = _int("RATE_LIMIT_SCANS_PER_MIN", 10)
RATE_LIMIT_BATCHES_PER_HOUR = _int("RATE_LIMIT_BATCHES_PER_HOUR", 3)
RATE_LIMIT_READS_PER_MIN = _int("RATE_LIMIT_READS_PER_MIN", 60)

# Total scans per day across ALL users. Set it just below your Gemini / threat-feed quota.
GLOBAL_SCANS_PER_DAY = _int("GLOBAL_SCANS_PER_DAY", 1000)

# Saved scans older than this are deleted at server start (0 = keep forever)
HISTORY_RETENTION_DAYS = _int("HISTORY_RETENTION_DAYS", 30)
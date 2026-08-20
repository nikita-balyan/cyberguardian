import os
from dotenv import load_dotenv

load_dotenv()

GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

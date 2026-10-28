import os
from pathlib import Path
from dotenv import load_dotenv

# Base directories
BACKEND_DIR = Path(__file__).resolve().parent.parent
ROOT_DIR = BACKEND_DIR.parent

# Load environment variables cleanly (backend .env takes precedence, falling back to root .env)
if (BACKEND_DIR / ".env").exists():
    load_dotenv(BACKEND_DIR / ".env", override=False)
if (ROOT_DIR / ".env").exists():
    load_dotenv(ROOT_DIR / ".env", override=False)

# Configuration values
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8001"))

# Proxy rotation: opt-in, only uses user-provided proxies
ENABLE_PROXY_ROTATION = os.getenv("ENABLE_PROXY_ROTATION", "false").lower() in ("true", "1", "yes")
PROXY_LIST = os.getenv("PROXY_LIST", "").strip()

# Cache directory
CACHE_DIR = BACKEND_DIR / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)


def get_gemini_api_key() -> str:
    """Return configured Gemini API key or empty string."""
    return os.getenv("GEMINI_API_KEY", "").strip() or GEMINI_API_KEY

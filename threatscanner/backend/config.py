"""
Configuration — reads from environment variables or .env file.
Copy .env.example to .env and fill in your API keys.
"""
import os
from dotenv import load_dotenv

load_dotenv()

SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "")
VIRUSTOTAL_API_KEY    = os.getenv("VIRUSTOTAL_API_KEY", "")
REDIS_URL             = os.getenv("REDIS_URL", "redis://localhost:6379")

# Rate limiting
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "30"))
RATE_LIMIT_WINDOW   = int(os.getenv("RATE_LIMIT_WINDOW",   "60"))

# File upload
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))  # 10 MB

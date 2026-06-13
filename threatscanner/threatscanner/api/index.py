import sys
import os

# Add backend directory to Python search path
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "backend"))

from backend.main import app

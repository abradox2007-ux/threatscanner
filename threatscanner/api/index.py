import sys
import os

# Add threatscanner and backend directories to Python search path
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "threatscanner"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "threatscanner", "backend"))

from backend.main import app

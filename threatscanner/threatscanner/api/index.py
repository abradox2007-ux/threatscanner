import sys
import os

# Add threatscanner directory to Python search path so we can import 'backend'
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
# Add backend directory to Python search path so internal absolute imports work
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "backend"))

from backend.main import app

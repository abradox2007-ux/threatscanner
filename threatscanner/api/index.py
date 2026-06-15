import sys
import os

# Get absolute path of the project root (parent directory of api/)
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Add root directory to python path so we can import 'backend'
sys.path.append(root_dir)
# Add backend directory to python path so internal absolute imports work
sys.path.append(os.path.join(root_dir, "backend"))

from backend.main import app


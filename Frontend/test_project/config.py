# config.py
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get API key from environment variable
BRAVE_API_KEY = os.getenv('BRAVE_API_KEY')
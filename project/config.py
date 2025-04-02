# config.py
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get API key from environment variable
BRAVE_API_KEY = os.getenv('BRAVE_API_KEY')
NVD_gist_api_key = os.getenv('NVD_API_KEY')
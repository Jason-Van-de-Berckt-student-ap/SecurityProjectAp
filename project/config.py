# config.py
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get API key from environment variable
BRAVE_API_KEY = os.getenv('BRAVE_API_KEY')
NVD_gist_api_key = os.getenv('NVD_API_KEY')

class Config:
    """Configuration class for the Flask application."""
    # Flask configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev')
    
    # SSL/TLS configuration
    SSL_VERIFY = True
    
    # Database configuration
    DATABASE = 'easm.db'
    
    # API Keys
    BRAVE_API_KEY = BRAVE_API_KEY
    NVD_API_KEY = NVD_gist_api_key
    
    # Security headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'self'",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0'
    }
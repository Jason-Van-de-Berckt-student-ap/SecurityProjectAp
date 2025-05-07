"""
EASM Application - External Attack Surface Management Tool

This tool scans domains for DNS records, SSL certificates, vulnerabilities,
subdomains, and related domains to help map the external attack surface.
"""
import os
import urllib3
from flask import Flask
import sqlite3
from config import Config

# Configure urllib3 to use system certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
os.environ['REQUESTS_CA_BUNDLE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cacert.pem')

# Create Flask application
app = Flask(__name__)
app.config.from_object(Config)

# Ensure required directories exist
os.makedirs('uploads', exist_ok=True)
os.makedirs('results', exist_ok=True)

# Database setup
def setup_database():
    """Create the SQLite database and required tables if they don't exist."""
    conn = sqlite3.connect('easm.db')
    c = conn.cursor()
    
    # Create scans table with batch information
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY,
                  domain TEXT,
                  scan_date TIMESTAMP,
                  dns_records TEXT,
                  ssl_info TEXT,
                  vulnerabilities TEXT,
                  subdomains TEXT,
                  related_domains TEXT,
                  onion_links TEXT,
                  batch_id TEXT,
                  is_batch_scan BOOLEAN DEFAULT 0)''')
    
    # Create batch_scans table to track batch operations
    c.execute('''CREATE TABLE IF NOT EXISTS batch_scans
                 (batch_id TEXT PRIMARY KEY,
                  created_at TIMESTAMP,
                  total_domains INTEGER,
                  completed_domains INTEGER DEFAULT 0,
                  status TEXT DEFAULT 'pending')''')
    
    conn.commit()
    conn.close()

# Register blueprints
def register_blueprints(app):
    """Register all blueprint routes with the Flask application."""
    from routes import all_blueprints
    
    for blueprint in all_blueprints:
        app.register_blueprint(blueprint)

# Initialize app
def init_app():
    """Initialize the Flask application."""
    # Set up the database
    setup_database()
    
    # Register blueprints
    register_blueprints(app)
    
    return app

# Create and initialize the application
app = init_app()

# Run the application
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
#!/bin/bash
# EASM Application Setup Script
# This script sets up the complete EASM application with all optimizations

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check Python version
    if command_exists python3; then
        python_version=$(python3 --version | awk '{print $2}')
        log "Python version: $python_version"
        
        # Check if Python 3.8 or higher
        if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
            error "Python 3.8 or higher is required"
            exit 1
        fi
    else
        error "Python 3 is not installed"
        exit 1
    fi
    
    # Check for pip
    if ! command_exists pip3; then
        error "pip3 is not installed"
        exit 1
    fi
    
    # Check for git
    if ! command_exists git; then
        warn "Git is not installed. Some features may not work."
    fi
    
    # Check available memory
    available_memory=$(free -m | awk 'NR==2{printf "%d", $7}')
    if [ "$available_memory" -lt 1024 ]; then
        warn "Available memory is less than 1GB. Application may run slowly."
    fi
    
    # Check disk space
    available_disk=$(df / | awk 'NR==2{printf "%d", $4/1024}')
    if [ "$available_disk" -lt 2048 ]; then
        warn "Available disk space is less than 2GB. Consider freeing up space."
    fi
    
    log "System requirements check completed"
}

# Function to create directory structure
create_directories() {
    log "Creating directory structure..."
    
    directories=(
        "logs"
        "uploads"
        "results"
        "config"
        "backups"
        "temp"
        "static/js"
        "static/css"
        "static/images"
        "templates/auth"
        "templates/monitoring"
    )
    
    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            log "Created directory: $dir"
        fi
    done
}

# Function to set up Python virtual environment
setup_virtualenv() {
    log "Setting up Python virtual environment..."
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        log "Created virtual environment"
    fi
    
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    log "Virtual environment activated"
}

# Function to install Python dependencies
install_dependencies() {
    log "Installing Python dependencies..."
    
    # Create requirements.txt if it doesn't exist
    if [ ! -f "requirements.txt" ]; then
        cat > requirements.txt << EOF
# Core Flask framework
Flask==2.3.3
Flask-CORS==4.0.0

# Database and ORM
SQLAlchemy==2.0.21
psycopg2-binary==2.9.7

# Caching
redis==4.6.0

# Authentication and Security
PyJWT==2.8.0
bcrypt==4.0.1
cryptography==41.0.4

# HTTP and networking
requests==2.31.0
urllib3==2.0.4
dnspython==2.4.2

# SSL and certificates
pyOpenSSL==23.2.0
certifi==2023.7.22

# Web scraping and parsing
beautifulsoup4==4.12.2
lxml==4.9.3

# System monitoring
psutil==5.9.5

# Data processing
pandas==2.0.3
numpy==1.24.3

# Configuration and environment
python-dotenv==1.0.0

# Logging and monitoring
structlog==23.1.0

# Background tasks
celery==5.3.1

# Development and testing
pytest==7.4.0
pytest-flask==1.2.0
coverage==7.3.0

# Production server
gunicorn==21.2.0
EOF
        log "Created requirements.txt"
    fi
    
    # Install requirements
    pip install -r requirements.txt
    
    log "Python dependencies installed"
}

# Function to set up environment configuration
setup_environment() {
    log "Setting up environment configuration..."
    
    if [ ! -f ".env" ]; then
        if [ -f ".env.complete" ]; then
            cp .env.complete .env
            log "Copied .env.complete to .env"
        else
            cat > .env << EOF
# Basic EASM Configuration
FLASK_ENV=development
SECRET_KEY=$(openssl rand -hex 32)
USE_SQLITE=true
SQLITE_DB=easm.db
USE_REDIS=false
LOG_LEVEL=INFO
SCAN_MAX_WORKERS=4
MAX_WORKERS=4
BRAVE_API_KEY=
EOF
            log "Created basic .env file"
        fi
        
        warn "Please review and customize the .env file for your environment"
    else
        log "Environment file already exists"
    fi
}

# Function to initialize database
initialize_database() {
    log "Initializing database..."
    
    # Run database initialization script
    python3 -c "
import os
import sqlite3
from datetime import datetime

# Create SQLite database
conn = sqlite3.connect('easm.db')
c = conn.cursor()

# Create base tables
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

c.execute('''CREATE TABLE IF NOT EXISTS batch_scans
             (batch_id TEXT PRIMARY KEY,
              created_at TIMESTAMP,
              total_domains INTEGER,
              completed_domains INTEGER DEFAULT 0,
              status TEXT DEFAULT 'pending')''')

conn.commit()
conn.close()
print('Database initialized successfully')
"
    
    log "Database initialized"
}

# Function to set up SSL certificates for development
setup_ssl() {
    log "Setting up SSL certificates for development..."
    
    if [ ! -d "ssl" ]; then
        mkdir ssl
    fi
    
    if [ ! -f "ssl/cert.pem" ] || [ ! -f "ssl/key.pem" ]; then
        # Generate self-signed certificate for development
        openssl req -x509 -newkey rsa:4096 -nodes -out ssl/cert.pem -keyout ssl/key.pem -days 365 \
            -subj "/C=US/ST=Development/L=Local/O=EASM/OU=Development/CN=localhost"
        
        log "Generated self-signed SSL certificate for development"
        warn "For production, use proper SSL certificates from a trusted CA"
    fi
}

# Function to set up systemd service (Linux only)
setup_systemd_service() {
    if [[ "$OSTYPE" == "linux-gnu"* ]] && command_exists systemctl; then
        log "Setting up systemd service..."
        
        service_file="/etc/systemd/system/easm.service"
        current_dir=$(pwd)
        
        # Create systemd service file
        sudo tee "$service_file" > /dev/null << EOF
[Unit]
Description=EASM Application
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$current_dir
Environment=PATH=$current_dir/venv/bin
ExecStart=$current_dir/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        
        # Reload systemd and enable service
        sudo systemctl daemon-reload
        sudo systemctl enable easm.service
        
        log "Systemd service created. Start with: sudo systemctl start easm"
    else
        warn "Systemd not available. Service setup skipped."
    fi
}

# Function to run tests
run_tests() {
    log "Running basic application tests..."
    
    # Create basic test
    cat > test_basic.py << EOF
import unittest
import sys
import os

# Add project directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class TestBasicSetup(unittest.TestCase):
    def test_imports(self):
        """Test that basic imports work"""
        try:
            import flask
            import sqlite3
            import requests
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Import failed: {e}")
    
    def test_database_connection(self):
        """Test database connection"""
        import sqlite3
        try:
            conn = sqlite3.connect('easm.db')
            conn.close()
            self.assertTrue(True)
        except Exception as e:
            self.fail(f"Database connection failed: {e}")

if __name__ == '__main__':
    unittest.main()
EOF
    
    python3 test_basic.py
    rm test_basic.py
    
    log "Basic tests passed"
}

# Function to create startup script
create_startup_script() {
    log "Creating startup script..."
    
    cat > start.sh << 'EOF'
#!/bin/bash
# EASM Application Startup Script

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    error "Virtual environment not found. Run setup.sh first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Check if .env file exists
if [ ! -f ".env" ]; then
    error ".env file not found. Run setup.sh first."
    exit 1
fi

# Load environment variables
export $(cat .env | grep -v '^#' | xargs)

# Start the application
log "Starting EASM application..."
log "Access the application at: http://localhost:5000"
log "Press Ctrl+C to stop the application"

# Run with gunicorn in production or flask dev server in development
if [ "$FLASK_ENV" = "production" ]; then
    log "Starting in production mode with Gunicorn..."
    gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 300 app:app
else
    log "Starting in development mode..."
    python app.py
fi
EOF
    
    chmod +x start.sh
    log "Created start.sh script"
}

# Function to create backup script
create_backup_script() {
    log "Creating backup script..."
    
    cat > backup.sh << 'EOF'
#!/bin/bash
# EASM Application Backup Script

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Create backup directory
backup_dir="backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$backup_dir"

log "Creating backup in: $backup_dir"

# Backup database
if [ -f "easm.db" ]; then
    cp easm.db "$backup_dir/"
    log "Database backed up"
fi

# Backup configuration
if [ -f ".env" ]; then
    cp .env "$backup_dir/"
    log "Configuration backed up"
fi

# Backup logs (last 7 days)
if [ -d "logs" ]; then
    find logs -name "*.log" -mtime -7 -exec cp {} "$backup_dir/" \;
    log "Recent logs backed up"
fi

# Backup user uploads
if [ -d "uploads" ]; then
    cp -r uploads "$backup_dir/"
    log "Uploads backed up"
fi

# Create backup archive
cd backups
tar -czf "$(basename $backup_dir).tar.gz" "$(basename $backup_dir)"
rm -rf "$(basename $backup_dir)"
cd ..

log "Backup completed: backups/$(basename $backup_dir).tar.gz"

# Clean old backups (keep last 7)
cd backups
ls -t *.tar.gz | tail -n +8 | xargs -r rm
cd ..

log "Old backups cleaned up"
EOF
    
    chmod +x backup.sh
    log "Created backup.sh script"
}

# Function to display completion message
show_completion_message() {
    echo
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}   EASM Application Setup Complete!    ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo
    echo -e "${BLUE}Next steps:${NC}"
    echo "1. Review and customize the .env file"
    echo "2. Start the application: ./start.sh"
    echo "3. Access the web interface at: http://localhost:5000"
    echo "4. Default admin login will be shown in the application logs"
    echo
    echo -e "${BLUE}Available scripts:${NC}"
    echo "• ./start.sh     - Start the application"
    echo "• ./backup.sh    - Create application backup"
    echo
    echo -e "${BLUE}System service (Linux):${NC}"
    if [[ "$OSTYPE" == "linux-gnu"* ]] && command_exists systemctl; then
        echo "• sudo systemctl start easm   - Start as system service"
        echo "• sudo systemctl stop easm    - Stop system service"
        echo "• sudo systemctl status easm  - Check service status"
    else
        echo "• Systemd service not available on this system"
    fi
    echo
    echo -e "${YELLOW}Important notes:${NC}"
    echo "• Change default admin password on first login"
    echo "• Configure external APIs in .env file for full functionality"
    echo "• For production deployment, use proper SSL certificates"
    echo "• Consider setting up proper database (PostgreSQL) for production"
    echo
}

# Main setup function
main() {
    echo -e "${BLUE}EASM Application Setup${NC}"
    echo "This script will set up the complete EASM application"
    echo
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        warn "Running as root. Consider running as a regular user."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Check system requirements
    check_requirements
    
    # Create directory structure
    create_directories
    
    # Set up virtual environment
    setup_virtualenv
    
    # Install dependencies
    install_dependencies
    
    # Set up environment configuration
    setup_environment
    
    # Initialize database
    initialize_database
    
    # Set up SSL certificates
    setup_ssl
    
    # Set up systemd service (Linux only)
    setup_systemd_service
    
    # Run basic tests
    run_tests
    
    # Create utility scripts
    create_startup_script
    create_backup_script
    
    # Show completion message
    show_completion_message
}

# Run main function
main "$@"

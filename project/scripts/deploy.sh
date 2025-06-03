#!/bin/bash

# EASM Application Automated Deployment Script
# This script automates the deployment process for production environments

set -e  # Exit on any error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/var/log/easm_deploy.log"
BACKUP_DIR="/opt/easm/backups"
DEPLOYMENT_ENV="${DEPLOYMENT_ENV:-production}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} $message"
            ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log "ERROR" "This script should not be run as root for security reasons"
        exit 1
    fi
}

# Check system requirements
check_requirements() {
    log "INFO" "Checking system requirements..."
    
    # Check Python version
    if ! python3 --version | grep -q "Python 3.1[1-9]"; then
        log "ERROR" "Python 3.11+ required"
        exit 1
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log "ERROR" "Docker is required but not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log "ERROR" "Docker Compose is required but not installed"
        exit 1
    fi
    
    # Check available disk space (minimum 5GB)
    available_space=$(df / | awk 'NR==2 {print $4}')
    required_space=5242880  # 5GB in KB
    
    if [[ $available_space -lt $required_space ]]; then
        log "ERROR" "Insufficient disk space. At least 5GB required"
        exit 1
    fi
    
    # Check memory (minimum 2GB)
    available_memory=$(free -m | awk 'NR==2{print $7}')
    required_memory=2048
    
    if [[ $available_memory -lt $required_memory ]]; then
        log "WARN" "Low memory detected. At least 2GB RAM recommended"
    fi
    
    log "INFO" "System requirements check passed"
}

# Create necessary directories
setup_directories() {
    log "INFO" "Setting up directory structure..."
    
    sudo mkdir -p /opt/easm/{config,logs,data,backups,ssl}
    sudo mkdir -p /var/log/easm
    
    # Set proper permissions
    sudo chown -R $USER:$USER /opt/easm
    sudo chown -R $USER:$USER /var/log/easm
    
    log "INFO" "Directory structure created"
}

# Backup existing deployment
backup_existing() {
    if [[ -d "/opt/easm/current" ]]; then
        log "INFO" "Creating backup of existing deployment..."
        
        backup_name="easm_backup_$(date +%Y%m%d_%H%M%S)"
        sudo mkdir -p "$BACKUP_DIR"
        
        # Create backup
        sudo tar -czf "$BACKUP_DIR/$backup_name.tar.gz" \
            -C /opt/easm current \
            --exclude='current/logs/*' \
            --exclude='current/results/*' \
            --exclude='current/__pycache__/*'
        
        # Keep only last 5 backups
        sudo find "$BACKUP_DIR" -name "easm_backup_*.tar.gz" -type f | \
            head -n -5 | xargs sudo rm -f
        
        log "INFO" "Backup created: $backup_name.tar.gz"
    fi
}

# Deploy application files
deploy_application() {
    log "INFO" "Deploying application files..."
    
    # Create deployment directory
    deployment_dir="/opt/easm/releases/$(date +%Y%m%d_%H%M%S)"
    sudo mkdir -p "$deployment_dir"
    
    # Copy application files
    sudo cp -r "$PROJECT_ROOT"/* "$deployment_dir/"
    
    # Set proper permissions
    sudo chown -R $USER:$USER "$deployment_dir"
    sudo chmod +x "$deployment_dir/scripts/"*.sh
    
    # Create symlink to current
    sudo rm -f /opt/easm/current
    sudo ln -s "$deployment_dir" /opt/easm/current
    
    log "INFO" "Application files deployed to $deployment_dir"
}

# Setup Python environment
setup_python_env() {
    log "INFO" "Setting up Python environment..."
    
    cd /opt/easm/current
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    if [[ -f "requirements.txt" ]]; then
        pip install -r requirements.txt
    else
        log "ERROR" "requirements.txt not found"
        exit 1
    fi
    
    log "INFO" "Python environment setup complete"
}

# Setup configuration files
setup_configuration() {
    log "INFO" "Setting up configuration files..."
    
    # Copy environment file if it doesn't exist
    if [[ ! -f "/opt/easm/config/.env" ]]; then
        if [[ -f "/opt/easm/current/.env.example" ]]; then
            cp /opt/easm/current/.env.example /opt/easm/config/.env
            log "WARN" "Created .env from example. Please review and update configuration"
        else
            log "ERROR" ".env.example not found"
            exit 1
        fi
    fi
    
    # Create symlink to config
    ln -sf /opt/easm/config/.env /opt/easm/current/.env
    
    # Setup logging configuration
    cat > /opt/easm/config/logging.conf << EOF
[loggers]
keys=root,easm

[handlers]
keys=consoleHandler,fileHandler

[formatters]
keys=simpleFormatter

[logger_root]
level=INFO
handlers=consoleHandler

[logger_easm]
level=INFO
handlers=consoleHandler,fileHandler
qualname=easm
propagate=0

[handler_consoleHandler]
class=StreamHandler
level=INFO
formatter=simpleFormatter
args=(sys.stdout,)

[handler_fileHandler]
class=FileHandler
level=INFO
formatter=simpleFormatter
args=('/var/log/easm/application.log',)

[formatter_simpleFormatter]
format=%(asctime)s - %(name)s - %(levelname)s - %(message)s
EOF
    
    log "INFO" "Configuration setup complete"
}

# Setup database
setup_database() {
    log "INFO" "Setting up database..."
    
    cd /opt/easm/current
    
    # Check if Docker Compose services are running
    if ! docker-compose ps | grep -q "postgres.*Up"; then
        log "INFO" "Starting database services..."
        docker-compose up -d postgres redis
        
        # Wait for services to be ready
        log "INFO" "Waiting for database to be ready..."
        for i in {1..30}; do
            if docker-compose exec -T postgres pg_isready -U easm_user -d easm_db; then
                break
            fi
            sleep 2
        done
    fi
    
    # Run migrations
    source venv/bin/activate
    python -c "
from services.migration_service import DatabaseMigration
import os

# Get database config from environment
db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 5432)),
    'database': os.getenv('DB_NAME', 'easm_db'),
    'user': os.getenv('DB_USER', 'easm_user'),
    'password': os.getenv('DB_PASSWORD', 'easm_pass')
}

migration = DatabaseMigration(db_config)
migration.migrate_up()
print('Database migrations completed')
"
    
    log "INFO" "Database setup complete"
}

# Setup SSL certificates
setup_ssl() {
    log "INFO" "Setting up SSL certificates..."
    
    ssl_dir="/opt/easm/ssl"
    
    if [[ ! -f "$ssl_dir/cert.pem" ]] || [[ ! -f "$ssl_dir/key.pem" ]]; then
        log "INFO" "Generating self-signed SSL certificate..."
        
        # Generate self-signed certificate
        openssl req -x509 -newkey rsa:4096 -keyout "$ssl_dir/key.pem" \
            -out "$ssl_dir/cert.pem" -days 365 -nodes \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
        
        # Set proper permissions
        chmod 600 "$ssl_dir/key.pem"
        chmod 644 "$ssl_dir/cert.pem"
        
        log "WARN" "Self-signed certificate created. Replace with proper certificate for production"
    fi
    
    log "INFO" "SSL setup complete"
}

# Setup systemd service
setup_systemd_service() {
    log "INFO" "Setting up systemd service..."
    
    # Create systemd service file
    sudo tee /etc/systemd/system/easm.service > /dev/null << EOF
[Unit]
Description=EASM Security Scanner Application
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=/opt/easm/current
Environment=PATH=/opt/easm/current/venv/bin
ExecStart=/opt/easm/current/venv/bin/python app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=easm

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/easm /var/log/easm

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable service
    sudo systemctl daemon-reload
    sudo systemctl enable easm.service
    
    log "INFO" "Systemd service configured"
}

# Setup log rotation
setup_log_rotation() {
    log "INFO" "Setting up log rotation..."
    
    # Create logrotate configuration
    sudo tee /etc/logrotate.d/easm > /dev/null << EOF
/var/log/easm/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 644 $USER $USER
    postrotate
        systemctl reload easm
    endscript
}

/opt/easm/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 $USER $USER
}
EOF
    
    log "INFO" "Log rotation configured"
}

# Setup monitoring
setup_monitoring() {
    log "INFO" "Setting up monitoring..."
    
    # Create monitoring script
    cat > /opt/easm/scripts/health_check.sh << 'EOF'
#!/bin/bash

# Health check script for EASM application
curl -f http://localhost:5000/health > /dev/null 2>&1
exit_code=$?

if [[ $exit_code -eq 0 ]]; then
    echo "EASM application is healthy"
    exit 0
else
    echo "EASM application health check failed"
    exit 1
fi
EOF
    
    chmod +x /opt/easm/scripts/health_check.sh
    
    # Create cron job for health checks
    (crontab -l 2>/dev/null; echo "*/5 * * * * /opt/easm/scripts/health_check.sh >> /var/log/easm/health_check.log 2>&1") | crontab -
    
    log "INFO" "Monitoring setup complete"
}

# Start services
start_services() {
    log "INFO" "Starting services..."
    
    cd /opt/easm/current
    
    # Start Docker services
    docker-compose up -d
    
    # Wait for services to be ready
    sleep 10
    
    # Start EASM application
    sudo systemctl start easm.service
    
    # Check service status
    if sudo systemctl is-active --quiet easm.service; then
        log "INFO" "EASM service started successfully"
    else
        log "ERROR" "Failed to start EASM service"
        sudo systemctl status easm.service
        exit 1
    fi
    
    log "INFO" "All services started"
}

# Verify deployment
verify_deployment() {
    log "INFO" "Verifying deployment..."
    
    # Wait for application to be ready
    sleep 15
    
    # Check health endpoint
    if curl -f http://localhost:5000/health > /dev/null 2>&1; then
        log "INFO" "Health check passed"
    else
        log "ERROR" "Health check failed"
        exit 1
    fi
    
    # Check detailed health
    if curl -f http://localhost:5000/health/detailed > /dev/null 2>&1; then
        log "INFO" "Detailed health check passed"
    else
        log "WARN" "Detailed health check failed (some components may be starting)"
    fi
    
    log "INFO" "Deployment verification complete"
}

# Cleanup old releases
cleanup_old_releases() {
    log "INFO" "Cleaning up old releases..."
    
    # Keep only last 3 releases
    if [[ -d "/opt/easm/releases" ]]; then
        find /opt/easm/releases -maxdepth 1 -type d -name "20*" | \
            sort -r | tail -n +4 | xargs sudo rm -rf
    fi
    
    log "INFO" "Cleanup complete"
}

# Main deployment function
main() {
    log "INFO" "Starting EASM deployment..."
    
    check_root
    check_requirements
    setup_directories
    backup_existing
    deploy_application
    setup_python_env
    setup_configuration
    setup_ssl
    setup_database
    setup_systemd_service
    setup_log_rotation
    setup_monitoring
    start_services
    verify_deployment
    cleanup_old_releases
    
    log "INFO" "EASM deployment completed successfully!"
    log "INFO" "Application is available at: http://localhost:5000"
    log "INFO" "Health check: http://localhost:5000/health"
    log "INFO" "Logs: /var/log/easm/application.log"
}

# Handle script arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "backup")
        backup_existing
        ;;
    "verify")
        verify_deployment
        ;;
    "cleanup")
        cleanup_old_releases
        ;;
    "help")
        echo "Usage: $0 [deploy|backup|verify|cleanup|help]"
        echo "  deploy  - Full deployment (default)"
        echo "  backup  - Create backup only"
        echo "  verify  - Verify deployment only"
        echo "  cleanup - Cleanup old releases only"
        echo "  help    - Show this help"
        ;;
    *)
        log "ERROR" "Unknown command: $1"
        exit 1
        ;;
esac

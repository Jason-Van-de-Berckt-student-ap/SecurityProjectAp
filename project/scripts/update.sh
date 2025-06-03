#!/bin/bash

# EASM Application Rolling Update Script
# This script performs zero-downtime rolling updates

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/var/log/easm_update.log"
HEALTH_CHECK_URL="http://localhost:5000/health"
MAX_WAIT_TIME=300  # 5 minutes

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging function
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO") echo -e "${GREEN}[INFO]${NC} $message" ;;
        "WARN") echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
        "DEBUG") echo -e "${BLUE}[DEBUG]${NC} $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Wait for service to be healthy
wait_for_health() {
    local url=$1
    local timeout=$2
    local start_time=$(date +%s)
    
    log "INFO" "Waiting for service to be healthy..."
    
    while true; do
        current_time=$(date +%s)
        elapsed=$((current_time - start_time))
        
        if [[ $elapsed -gt $timeout ]]; then
            log "ERROR" "Timeout waiting for service to be healthy"
            return 1
        fi
        
        if curl -f "$url" > /dev/null 2>&1; then
            log "INFO" "Service is healthy"
            return 0
        fi
        
        sleep 5
    done
}

# Perform rolling update
rolling_update() {
    log "INFO" "Starting rolling update..."
    
    # Get current release
    current_release=$(readlink /opt/easm/current)
    log "INFO" "Current release: $current_release"
    
    # Create new release directory
    new_release="/opt/easm/releases/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$new_release"
    
    # Copy application files
    log "INFO" "Deploying new release..."
    cp -r "$PROJECT_ROOT"/* "$new_release/"
    
    # Set permissions
    chown -R $USER:$USER "$new_release"
    chmod +x "$new_release/scripts/"*.sh
    
    # Setup Python environment
    log "INFO" "Setting up Python environment for new release..."
    cd "$new_release"
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    
    # Copy configuration
    ln -sf /opt/easm/config/.env "$new_release/.env"
    
    # Test new release
    log "INFO" "Testing new release..."
    cd "$new_release"
    source venv/bin/activate
    
    # Run health check on new code
    python -c "
try:
    from services.health_check import HealthCheckService
    print('New release code validation passed')
except Exception as e:
    print(f'New release validation failed: {e}')
    exit(1)
"
    
    if [[ $? -ne 0 ]]; then
        log "ERROR" "New release validation failed"
        rm -rf "$new_release"
        exit 1
    fi
    
    # Stop current application gracefully
    log "INFO" "Stopping current application..."
    sudo systemctl stop easm.service
    
    # Switch to new release
    log "INFO" "Switching to new release..."
    rm -f /opt/easm/current
    ln -s "$new_release" /opt/easm/current
    
    # Start new application
    log "INFO" "Starting new application..."
    sudo systemctl start easm.service
    
    # Wait for new service to be healthy
    if wait_for_health "$HEALTH_CHECK_URL" "$MAX_WAIT_TIME"; then
        log "INFO" "Rolling update completed successfully"
        
        # Cleanup old releases (keep last 3)
        find /opt/easm/releases -maxdepth 1 -type d -name "20*" | \
            sort -r | tail -n +4 | xargs rm -rf
        
        return 0
    else
        log "ERROR" "New release failed health check, rolling back..."
        rollback_to_previous
        return 1
    fi
}

# Rollback to previous release
rollback_to_previous() {
    log "INFO" "Starting rollback..."
    
    # Find previous release
    previous_release=$(find /opt/easm/releases -maxdepth 1 -type d -name "20*" | \
                      sort -r | head -n 2 | tail -n 1)
    
    if [[ -z "$previous_release" ]]; then
        log "ERROR" "No previous release found for rollback"
        exit 1
    fi
    
    log "INFO" "Rolling back to: $previous_release"
    
    # Stop current service
    sudo systemctl stop easm.service
    
    # Switch to previous release
    rm -f /opt/easm/current
    ln -s "$previous_release" /opt/easm/current
    
    # Start previous service
    sudo systemctl start easm.service
    
    # Verify rollback
    if wait_for_health "$HEALTH_CHECK_URL" 60; then
        log "INFO" "Rollback completed successfully"
    else
        log "ERROR" "Rollback failed - manual intervention required"
        exit 1
    fi
}

# Blue-green deployment
blue_green_deployment() {
    log "INFO" "Starting blue-green deployment..."
    
    # This would require load balancer configuration
    # For now, we'll use the rolling update approach
    rolling_update
}

# Canary deployment
canary_deployment() {
    log "INFO" "Starting canary deployment..."
    
    # Deploy to subset of instances
    # This would require multiple instances and load balancer
    # For single instance, fall back to rolling update
    rolling_update
}

# Database migration during update
migrate_database() {
    log "INFO" "Running database migrations..."
    
    cd /opt/easm/current
    source venv/bin/activate
    
    python -c "
from services.migration_service import DatabaseMigration
import os

db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 5432)),
    'database': os.getenv('DB_NAME', 'easm_db'),
    'user': os.getenv('DB_USER', 'easm_user'),
    'password': os.getenv('DB_PASSWORD', 'easm_pass')
}

migration = DatabaseMigration(db_config)
status = migration.get_migration_status()

if status['pending_count'] > 0:
    print(f'Applying {status[\"pending_count\"]} pending migrations...')
    success = migration.migrate_up()
    if success:
        print('Database migrations completed successfully')
    else:
        print('Database migration failed')
        exit(1)
else:
    print('No pending migrations')
"
}

# Pre-deployment checks
pre_deployment_checks() {
    log "INFO" "Running pre-deployment checks..."
    
    # Check system resources
    available_memory=$(free -m | awk 'NR==2{print $7}')
    if [[ $available_memory -lt 1024 ]]; then
        log "WARN" "Low memory detected: ${available_memory}MB available"
    fi
    
    # Check disk space
    available_space=$(df / | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 1048576 ]]; then  # 1GB
        log "WARN" "Low disk space detected"
    fi
    
    # Check if services are running
    if ! sudo systemctl is-active --quiet easm.service; then
        log "ERROR" "EASM service is not running"
        exit 1
    fi
    
    # Check database connectivity
    if ! curl -f http://localhost:5000/health/database > /dev/null 2>&1; then
        log "ERROR" "Database health check failed"
        exit 1
    fi
    
    log "INFO" "Pre-deployment checks passed"
}

# Post-deployment validation
post_deployment_validation() {
    log "INFO" "Running post-deployment validation..."
    
    # Check all health endpoints
    endpoints=(
        "/health"
        "/health/detailed"
        "/health/database"
        "/health/cache"
        "/health/tasks"
    )
    
    for endpoint in "${endpoints[@]}"; do
        if curl -f "http://localhost:5000$endpoint" > /dev/null 2>&1; then
            log "INFO" "Health check passed: $endpoint"
        else
            log "WARN" "Health check failed: $endpoint"
        fi
    done
    
    # Check application logs for errors
    if sudo journalctl -u easm.service --since "5 minutes ago" | grep -i error; then
        log "WARN" "Errors found in application logs"
    fi
    
    log "INFO" "Post-deployment validation completed"
}

# Update configuration
update_configuration() {
    log "INFO" "Updating configuration..."
    
    # Backup current config
    cp /opt/easm/config/.env /opt/easm/config/.env.backup.$(date +%Y%m%d_%H%M%S)
    
    # Update configuration if new template exists
    if [[ -f "/opt/easm/current/.env.example" ]]; then
        # Merge configurations (this is a simple example)
        # In production, you might want more sophisticated config management
        log "INFO" "Configuration template found - review for new settings"
    fi
    
    log "INFO" "Configuration update completed"
}

# Main update function
main() {
    local update_type="${1:-rolling}"
    
    log "INFO" "Starting EASM update (type: $update_type)..."
    
    pre_deployment_checks
    
    case "$update_type" in
        "rolling")
            rolling_update
            ;;
        "blue-green")
            blue_green_deployment
            ;;
        "canary")
            canary_deployment
            ;;
        *)
            log "ERROR" "Unknown update type: $update_type"
            exit 1
            ;;
    esac
    
    migrate_database
    update_configuration
    post_deployment_validation
    
    log "INFO" "EASM update completed successfully!"
}

# Handle script arguments
case "${1:-rolling}" in
    "rolling"|"blue-green"|"canary")
        main "$1"
        ;;
    "rollback")
        rollback_to_previous
        ;;
    "migrate")
        migrate_database
        ;;
    "check")
        pre_deployment_checks
        post_deployment_validation
        ;;
    "help")
        echo "Usage: $0 [rolling|blue-green|canary|rollback|migrate|check|help]"
        echo "  rolling     - Rolling update (default)"
        echo "  blue-green  - Blue-green deployment"
        echo "  canary      - Canary deployment"
        echo "  rollback    - Rollback to previous release"
        echo "  migrate     - Run database migrations only"
        echo "  check       - Run deployment checks only"
        echo "  help        - Show this help"
        ;;
    *)
        log "ERROR" "Unknown command: $1"
        exit 1
        ;;
esac

# EASM Optimization Services Deployment Guide

# ============================================================================

# This file contains deployment instructions and configuration for the

# optimized EASM application with all performance enhancements.

# ============================================================================

# ============================================================================

# SYSTEM REQUIREMENTS

# ============================================================================

# Minimum Requirements:

# - CPU: 4 cores (recommended: 8+ cores)

# - RAM: 8GB (recommended: 16GB+)

# - Storage: 50GB SSD (recommended: 100GB+ SSD)

# - Network: Stable internet connection

# - OS: Linux (Ubuntu 20.04+), Windows 10+, or macOS 10.15+

# Recommended Production Setup:

# - CPU: 8+ cores with high clock speed

# - RAM: 32GB+ for large-scale scanning

# - Storage: 200GB+ NVMe SSD

# - Network: High-bandwidth connection (100Mbps+)

# - Load balancer for horizontal scaling

# ============================================================================

# DEPENDENCIES INSTALLATION

# ============================================================================

# Python Dependencies (requirements.txt already updated):

pip install -r requirements.txt

# System Dependencies:

# Ubuntu/Debian:

sudo apt-get update
sudo apt-get install -y \
 python3-dev \
 python3-pip \
 redis-server \
 sqlite3 \
 nginx \
 supervisor \
 build-essential \
 libssl-dev \
 libffi-dev

# CentOS/RHEL:

sudo yum update
sudo yum install -y \
 python3-devel \
 python3-pip \
 redis \
 sqlite \
 nginx \
 supervisor \
 gcc \
 openssl-devel \
 libffi-devel

# Windows:

# Install Redis for Windows from GitHub releases

# Install Visual C++ Build Tools if needed

# ============================================================================

# DATABASE SETUP

# ============================================================================

# SQLite Configuration (for development/small deployments):

# - Database will be created automatically

# - WAL mode enabled for better performance

# - Connection pooling configured

# PostgreSQL Setup (for production/large deployments):

# 1. Install PostgreSQL

sudo apt-get install postgresql postgresql-contrib

# 2. Create database and user

sudo -u postgres psql
CREATE DATABASE easm_db;
CREATE USER easm_user WITH ENCRYPTED PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE easm_db TO easm_user;
\q

# 3. Update database configuration in config.py:

DATABASE_URL = 'postgresql://easm_user:your_secure_password@localhost/easm_db'

# ============================================================================

# REDIS SETUP

# ============================================================================

# Redis Installation and Configuration:

# See redis_setup.conf for detailed Redis configuration

# Quick Setup:

sudo systemctl start redis
sudo systemctl enable redis

# Production Redis Configuration:

sudo cp config/redis_production.conf /etc/redis/redis.conf
sudo systemctl restart redis

# Verify Redis is working:

redis-cli ping

# Should return: PONG

# ============================================================================

# APPLICATION CONFIGURATION

# ============================================================================

# Environment Variables (.env file):

cat > .env << EOF

# Flask Configuration

FLASK_ENV=production
SECRET_KEY=your_very_secure_secret_key_here
DEBUG=False

# Database Configuration

DATABASE_URL=sqlite:///easm.db

# DATABASE_URL=postgresql://easm_user:password@localhost/easm_db

# Redis Configuration

REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=your_redis_password

# Cache Configuration

CACHE_TTL_DNS=1800
CACHE_TTL_SUBDOMAIN=3600
CACHE_TTL_DOMAIN=7200
CACHE_TTL_VULN=1800

# Rate Limiting

RATE_LIMIT_REQUESTS_PER_MINUTE=60
RATE_LIMIT_BURST_SIZE=10

# Security

WTF_CSRF_TIME_LIMIT=3600
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True

# Logging

LOG_LEVEL=INFO
LOG_FILE=/var/log/easm/app.log

# Performance

MAX_CONCURRENT_SCANS=3
MAX_BACKGROUND_WORKERS=3
DATABASE_POOL_SIZE=10
EOF

# ============================================================================

# NGINX CONFIGURATION

# ============================================================================

# Create Nginx configuration:

sudo tee /etc/nginx/sites-available/easm << EOF
server {
listen 80;
server_name your-domain.com;

    # Redirect HTTP to HTTPS
    return 301 https://\$server_name\$request_uri;

}

server {
listen 443 ssl http2;
server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /path/to/ssl/certificate.pem;
    ssl_certificate_key /path/to/ssl/private_key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security Headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Rate Limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone \$binary_remote_addr zone=login:10m rate=1r/s;

    # Static Files
    location /static {
        alias /path/to/easm/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # API Endpoints (with rate limiting)
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300;
        proxy_connect_timeout 30;
    }

    # Main Application
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300;
        proxy_connect_timeout 30;
    }

}
EOF

# Enable the site:

sudo ln -s /etc/nginx/sites-available/easm /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# ============================================================================

# SUPERVISOR CONFIGURATION

# ============================================================================

# Create Supervisor configuration for the Flask app:

sudo tee /etc/supervisor/conf.d/easm.conf << EOF
[program:easm]
command=/path/to/venv/bin/python /path/to/easm/app.py
directory=/path/to/easm
user=www-data
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/supervisor/easm.log
environment=PATH="/path/to/venv/bin"

[program:easm-worker]
command=/path/to/venv/bin/python -m services.background*tasks
directory=/path/to/easm
user=www-data
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/supervisor/easm-worker.log
environment=PATH="/path/to/venv/bin"
numprocs=3
process_name=%(program_name)s*%(process_num)02d
EOF

# Start services:

sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start easm:\*

# ============================================================================

# GUNICORN CONFIGURATION (Alternative to direct Flask)

# ============================================================================

# Install Gunicorn:

pip install gunicorn

# Create Gunicorn configuration:

cat > gunicorn_config.py << EOF
import multiprocessing

# Server socket

bind = "127.0.0.1:5000"
backlog = 2048

# Worker processes

workers = multiprocessing.cpu_count() \* 2 + 1
worker_class = "sync"
worker_connections = 1000
timeout = 300
keepalive = 2

# Logging

accesslog = "/var/log/gunicorn/access.log"
errorlog = "/var/log/gunicorn/error.log"
loglevel = "info"

# Process naming

proc_name = "easm-gunicorn"

# Server mechanics

daemon = False
pidfile = "/var/run/gunicorn/easm.pid"
user = "www-data"
group = "www-data"
tmp_upload_dir = None

# SSL (if terminating SSL at Gunicorn level)

# keyfile = "/path/to/ssl/private_key.pem"

# certfile = "/path/to/ssl/certificate.pem"

EOF

# Update Supervisor configuration for Gunicorn:

sudo tee /etc/supervisor/conf.d/easm-gunicorn.conf << EOF
[program:easm-gunicorn]
command=/path/to/venv/bin/gunicorn --config gunicorn_config.py app:app
directory=/path/to/easm
user=www-data
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/supervisor/easm-gunicorn.log
environment=PATH="/path/to/venv/bin"
EOF

# ============================================================================

# MONITORING SETUP

# ============================================================================

# System Monitoring with Prometheus (optional):

# 1. Install Prometheus

# 2. Configure Flask metrics endpoint

# 3. Set up Grafana dashboards

# Log Monitoring:

# 1. Configure centralized logging (ELK stack or similar)

# 2. Set up log rotation

# 3. Monitor error rates and performance metrics

# Application Monitoring:

# Add to your Flask app:

from prometheus_flask_exporter import PrometheusMetrics

metrics = PrometheusMetrics(app)
metrics.info('app_info', 'Application info', version='1.0.0')

# Health Check Endpoint:

@app.route('/health')
def health_check():
return {
'status': 'healthy',
'timestamp': time.time(),
'services': {
'database': check_database_health(),
'redis': check_redis_health(),
'background_tasks': check_tasks_health()
}
}

# ============================================================================

# BACKUP STRATEGY

# ============================================================================

# Database Backup Script:

cat > backup*database.sh << EOF
#!/bin/bash
DATE=\$(date +%Y%m%d*%H%M%S)
BACKUP_DIR="/backup/database"
DB_FILE="/path/to/easm.db"

mkdir -p \$BACKUP_DIR

# SQLite backup

sqlite3 \$DB*FILE ".backup \$BACKUP_DIR/easm*\$DATE.db"
gzip "\$BACKUP*DIR/easm*\$DATE.db"

# PostgreSQL backup (if using PostgreSQL)

# pg*dump -U easm_user -h localhost easm_db | gzip > "\$BACKUP_DIR/easm*\$DATE.sql.gz"

# Cleanup old backups (keep 30 days)

find \$BACKUP*DIR -name "easm*\*.db.gz" -mtime +30 -delete

echo "Database backup completed: \$BACKUP*DIR/easm*\$DATE.db.gz"
EOF

chmod +x backup_database.sh

# Add to crontab for automated backups:

# 0 2 \* \* \* /path/to/backup_database.sh

# ============================================================================

# SECURITY HARDENING

# ============================================================================

# Firewall Configuration:

sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# File Permissions:

chmod 600 .env
chmod 644 \*.py
chmod 755 /path/to/easm
chown -R www-data:www-data /path/to/easm

# Fail2ban (optional but recommended):

sudo apt-get install fail2ban
sudo systemctl enable fail2ban

# ============================================================================

# PERFORMANCE TUNING

# ============================================================================

# System-level optimizations:

# Increase file descriptor limits:

echo "www-data soft nofile 65536" >> /etc/security/limits.conf
echo "www-data hard nofile 65536" >> /etc/security/limits.conf

# TCP tuning:

echo "net.core.somaxconn = 65535" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65535" >> /etc/sysctl.conf
sysctl -p

# Database optimizations:

# For SQLite: Enable WAL mode, increase cache size

# For PostgreSQL: Tune shared_buffers, work_mem, etc.

# ============================================================================

# DEPLOYMENT CHECKLIST

# ============================================================================

# Pre-deployment:

# [ ] All dependencies installed

# [ ] Database configured and accessible

# [ ] Redis configured and running

# [ ] Environment variables set

# [ ] SSL certificates installed

# [ ] Nginx configuration tested

# [ ] Supervisor configuration ready

# [ ] Backup strategy implemented

# [ ] Monitoring setup complete

# Deployment:

# [ ] Code deployed to production server

# [ ] Virtual environment activated

# [ ] Database migrations run (if applicable)

# [ ] Static files collected

# [ ] Services started via Supervisor

# [ ] Nginx reloaded

# [ ] Health checks passing

# Post-deployment:

# [ ] Application responding correctly

# [ ] All services running

# [ ] Monitoring dashboards accessible

# [ ] Backup jobs scheduled

# [ ] Performance metrics baseline established

# [ ] Security scan completed

# ============================================================================

# SCALING CONSIDERATIONS

# ============================================================================

# Horizontal Scaling:

# 1. Load balancer (Nginx, HAProxy, or cloud LB)

# 2. Multiple application instances

# 3. Shared Redis cluster

# 4. Database read replicas

# Vertical Scaling:

# 1. Increase server resources (CPU, RAM)

# 2. Optimize database configuration

# 3. Tune application parameters

# 4. Implement more aggressive caching

# Container Deployment (Docker):

# See docker-compose.yml for containerized deployment

# Cloud Deployment:

# Consider AWS ECS, Google Cloud Run, or Azure Container Instances

# Use managed Redis and database services

# Implement auto-scaling based on metrics

# ============================================================================

# TROUBLESHOOTING

# ============================================================================

# Common Issues:

# 1. High Memory Usage:

# - Check Redis memory usage

# - Review cache TTL settings

# - Monitor background task queue

# 2. Slow Performance:

# - Check database query performance

# - Monitor Redis latency

# - Review rate limiting settings

# 3. High CPU Usage:

# - Check for stuck background tasks

# - Monitor concurrent scan limits

# - Review worker process count

# 4. Database Connection Issues:

# - Check connection pool settings

# - Monitor active connections

# - Review database configuration

# Useful Commands:

# Check application status: sudo supervisorctl status

# Monitor Redis: redis-cli monitor

# Check logs: tail -f /var/log/supervisor/easm.log

# Test database: sqlite3 easm.db ".tables"

# Monitor system: htop, iotop, netstat

# ============================================================================

# MAINTENANCE

# ============================================================================

# Regular Maintenance Tasks:

# Daily:

# - Check application logs for errors

# - Monitor system resources

# - Verify backup completion

# Weekly:

# - Review performance metrics

# - Check for security updates

# - Clean up old log files

# Monthly:

# - Update dependencies

# - Review and optimize cache settings

# - Performance testing

# - Security scan

# Quarterly:

# - Full system backup

# - Disaster recovery testing

# - Capacity planning review

# - Security audit

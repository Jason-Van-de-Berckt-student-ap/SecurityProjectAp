"""
EASM Application - External Attack Surface Management Tool

This tool scans domains for DNS records, SSL certificates, vulnerabilities,
subdomains, and related domains to help map the external attack surface.

Optimized version with advanced caching, parallel processing, and monitoring.
"""
import os
import logging
import urllib3
from flask import Flask, g, request, jsonify
import sqlite3
from config import Config

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Import optimization services
from services.database_manager import DatabaseManager
from services.cache_manager import CacheManager
from services.optimized_scanner import OptimizedScanner
from services.rate_limiter import RateLimiter
from services.background_tasks import BackgroundTaskManager
from services.health_check import health_bp, init_health_service
from services.security_service import SecurityService
from services.cache_warming import CacheWarmingService
from services.migration_service import DatabaseMigration
from services.auth_service import init_auth_service, get_auth_service
from services.logging_service import init_logging_service, get_logging_service, LogLevel, EventType

# Configure urllib3 to use system certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
os.environ['REQUESTS_CA_BUNDLE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cacert.pem')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create Flask application
app = Flask(__name__)
app.config.from_object(Config)

# Initialize optimization services
db_manager = None
cache_manager = None
scanner = None
rate_limiter = None
task_manager = None
security_service = None
cache_warming_service = None
auth_service = None
logging_service = None

# Ensure required directories exist
os.makedirs('uploads', exist_ok=True)
os.makedirs('results', exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs('config', exist_ok=True)

def init_optimization_services():
    """Initialize all optimization services."""
    global db_manager, cache_manager, scanner, rate_limiter, task_manager
    global security_service, cache_warming_service, auth_service, logging_service
    
    try:
        logger.info("Initializing optimization services...")
        
        # Use SQLite for development if PostgreSQL is not available
        use_sqlite = os.getenv('USE_SQLITE', 'true').lower() == 'true'
        
        if use_sqlite:
            # SQLite configuration for development
            db_config = {
                'type': 'sqlite',
                'database': os.getenv('SQLITE_DB', 'easm.db')
            }
        else:
            # PostgreSQL configuration for production
            db_config = {
                'type': 'postgresql',
                'host': os.getenv('DB_HOST', 'localhost'),
                'port': int(os.getenv('DB_PORT', 5432)),
                'database': os.getenv('DB_NAME', 'easm_db'),
                'user': os.getenv('DB_USER', 'easm_user'),
                'password': os.getenv('DB_PASSWORD', 'easm_pass'),
                'pool_size': int(os.getenv('DB_POOL_SIZE', 20)),
                'max_overflow': int(os.getenv('DB_MAX_OVERFLOW', 30))
            }
        
        # Redis configuration (optional for development)
        use_redis = os.getenv('USE_REDIS', 'false').lower() == 'true'
        
        if use_redis:
            redis_config = {
                'host': os.getenv('REDIS_HOST', 'localhost'),
                'port': int(os.getenv('REDIS_PORT', 6379)),
                'password': os.getenv('REDIS_PASSWORD', ''),
                'db': int(os.getenv('REDIS_DB', 0)),
                'max_connections': int(os.getenv('REDIS_MAX_CONNECTIONS', 50))
            }
        else:
            # Use in-memory cache for development
            redis_config = {'type': 'memory'}
        
        # Security configuration
        security_config = {
            'ALLOWED_HOSTS': os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(','),
            'SECURE_COOKIES': os.getenv('SECURE_COOKIES', 'false').lower() == 'true',
            'SESSION_TIMEOUT': int(os.getenv('SESSION_TIMEOUT', 3600)),
            'ALLOW_PRIVATE_IPS': os.getenv('ALLOW_PRIVATE_IPS', 'true').lower() == 'true'
        }
        
        # Authentication configuration
        auth_config = {
            'SECRET_KEY': os.getenv('SECRET_KEY', app.secret_key),
            'SESSION_TIMEOUT': int(os.getenv('SESSION_TIMEOUT', 3600)),
            'MAX_LOGIN_ATTEMPTS': int(os.getenv('MAX_LOGIN_ATTEMPTS', 5)),
            'LOCKOUT_DURATION': int(os.getenv('LOCKOUT_DURATION', 300))
        }
        
        # Logging configuration
        logging_config = {
            'LOG_LEVEL': os.getenv('LOG_LEVEL', 'INFO'),
            'LOG_TO_FILE': os.getenv('LOG_TO_FILE', 'true').lower() == 'true',
            'LOG_TO_DB': os.getenv('LOG_TO_DB', 'true').lower() == 'true',
            'LOG_TO_CONSOLE': os.getenv('LOG_TO_CONSOLE', 'true').lower() == 'true',
            'LOG_RETENTION_DAYS': int(os.getenv('LOG_RETENTION_DAYS', 30)),
            'PERFORMANCE_THRESHOLD': float(os.getenv('PERFORMANCE_THRESHOLD', 5.0)),
            'LOG_DIRECTORY': os.getenv('LOG_DIRECTORY', 'logs')
        }
          # Initialize services in order
        database_path = db_config.get('database', 'easm.db') if use_sqlite else None
        db_manager = DatabaseManager(database_path)
        cache_manager = CacheManager(redis_config)
        
        # Initialize logging service early
        logging_service = init_logging_service(db_manager, cache_manager, logging_config)
        
        # Initialize other services
        rate_limiter = RateLimiter(cache_manager)
        task_manager = BackgroundTaskManager(max_workers=int(os.getenv('MAX_WORKERS', 6)))
        security_service = SecurityService(security_config)
        
        # Initialize auth service
        auth_service = init_auth_service(db_manager, cache_manager, auth_config)
        
        # Initialize scanner with optimized settings
        scanner = OptimizedScanner(
            max_workers=int(os.getenv('SCAN_MAX_WORKERS', 6)),
            timeout=int(os.getenv('SCAN_TIMEOUT', 300))
        )
        
        cache_warming_service = CacheWarmingService(cache_manager, db_manager, scanner, task_manager)
        
        # Initialize health service
        init_health_service(db_manager, cache_manager, task_manager, rate_limiter)
        
        # Run database migrations if using PostgreSQL
        if not use_sqlite:
            try:
                migration = DatabaseMigration(db_config)
                migration.migrate_up()
            except Exception as e:
                logger.warning(f"Migration failed, continuing with existing schema: {e}")          # Log successful initialization
        if logging_service:
            logging_service.log_event(LogLevel.INFO, EventType.SYSTEM_EVENT, "Application services initialized successfully")
        
        logger.info("Optimization services initialized successfully")
        
    except Exception as e:
        import traceback
        logger.error(f"Failed to initialize optimization services: {e}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        # Don't raise in development mode, allow app to start with basic functionality
        if os.getenv('FLASK_ENV') == 'production':
            raise

@app.before_request
def before_request():
    """Set up request context."""
    import uuid
    
    # Generate unique request ID
    g.request_id = str(uuid.uuid4())
    
    # Set up service references
    g.db_manager = db_manager
    g.cache_manager = cache_manager
    g.scanner = scanner
    g.rate_limiter = rate_limiter
    g.task_manager = task_manager
    g.security_service = security_service
    g.cache_warming_service = cache_warming_service
    g.auth_service = auth_service
    g.logging_service = logging_service
    
    # Log request start
    if logging_service:
        logging_service.log_user_action(
            f"{request.method} {request.endpoint}",
            request.path,
            metadata={'request_id': g.request_id}
        )
    
    # Record domain access for cache warming if it's a scan request
    if request.endpoint in ['scan_domain', 'batch_scan'] and request.method == 'POST':
        domain = request.form.get('domain') or request.json.get('domain') if request.is_json else None
        if domain and cache_warming_service:
            cache_warming_service.record_domain_access(domain)

@app.after_request
def after_request(response):
    """Add security headers to all responses."""
    if security_service:
        headers = security_service.get_security_headers()
        for header, value in headers.items():
            response.headers[header] = value
    
    return response

# Register health check blueprint
app.register_blueprint(health_bp)

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
    # Initialize optimization services first
    init_optimization_services()
    
    # Set up the database
    setup_database()
    
    # Register blueprints
    register_blueprints(app)
    
    return app

# Create and initialize the application
app = init_app()

# Run the application
if __name__ == '__main__':
    # Start cache warming in background
    if cache_warming_service:
        try:
            cache_warming_service.start_background_warming()
        except Exception as e:
            logger.warning(f"Failed to start cache warming: {e}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
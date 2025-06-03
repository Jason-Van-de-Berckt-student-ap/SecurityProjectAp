"""
Authentication and Authorization Service for EASM Application.

This service provides user authentication, session management, and role-based access control.
"""
import hashlib
import secrets
import time
import jwt
from functools import wraps
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from flask import request, jsonify, session, g, current_app
import logging
import json # <--- ADDED: Import the json module

logger = logging.getLogger(__name__)

# Helper function to parse database timestamps into float (Unix timestamp)
def _parse_db_timestamp_to_float(ts_value: Any) -> Optional[float]:
    """
    Converts a database timestamp value (which could be datetime object or string)
    into a Unix timestamp (float).
    """
    if ts_value is None:
        return None
    if isinstance(ts_value, datetime):
        return ts_value.timestamp()
    if isinstance(ts_value, str):
        try:
            # Attempt parsing common ISO formats (e.g., 'YYYY-MM-DDTHH:MM:SS' or 'YYYY-MM-DD HH:MM:SS')
            # Replace space with 'T' for robust ISO parsing if needed
            dt_obj = datetime.fromisoformat(ts_value.replace(' ', 'T'))
            return dt_obj.timestamp()
        except ValueError:
            # Fallback for simpler SQL timestamp format 'YYYY-MM-DD HH:MM:SS' if fromisoformat fails
            try:
                dt_obj = datetime.strptime(ts_value, "%Y-%m-%d %H:%M:%S")
                return dt_obj.timestamp()
            except ValueError:
                logger.warning(f"Could not parse timestamp string '{ts_value}' to datetime. Returning None.")
                return None
    logger.warning(f"Unexpected type for timestamp value: {type(ts_value)}. Expected datetime or str. Returning None.")
    return None


class User:
    """User model class."""
    
    def __init__(self, user_id: str, username: str, email: str, role: str, 
                 created_at: float, last_login: Optional[float] = None, 
                 is_active: bool = True, preferences: Optional[Dict] = None):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.role = role
        self.created_at = created_at
        self.last_login = last_login
        self.is_active = is_active
        self.preferences = preferences or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary."""
        return {
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at,
            'last_login': self.last_login,
            'is_active': self.is_active,
            'preferences': self.preferences
        }
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission."""
        role_permissions = {
            'admin': ['scan', 'batch_scan', 'export', 'manage_users', 'view_logs', 'system_health'],
            'analyst': ['scan', 'batch_scan', 'export', 'view_logs'],
            'user': ['scan', 'export'],
            'viewer': ['export']
        }
        return permission in role_permissions.get(self.role, [])

class AuthService:
    """Authentication and authorization service."""
    
    def __init__(self, db_manager, cache_manager, config: Dict[str, Any]):
        self.db_manager = db_manager
        self.cache_manager = cache_manager
        self.config = config
        self.secret_key = config.get('SECRET_KEY', secrets.token_urlsafe(32))
        self.session_timeout = config.get('SESSION_TIMEOUT', 3600)
        self.max_login_attempts = config.get('MAX_LOGIN_ATTEMPTS', 5)
        self.lockout_duration = config.get('LOCKOUT_DURATION', 300)  # 5 minutes
        
        # Initialize database tables
        self._init_auth_tables()
    
    def _init_auth_tables(self):
        """Initialize authentication-related database tables."""
        try:
            # Users table
            self.db_manager.execute_query("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id VARCHAR(255) PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    salt VARCHAR(255) NOT NULL,
                    role VARCHAR(50) DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    preferences TEXT
                )
            """)
            
            # Sessions table
            self.db_manager.execute_query("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    session_id VARCHAR(255) PRIMARY KEY,
                    user_id VARCHAR(255) REFERENCES users(user_id),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    is_active BOOLEAN DEFAULT TRUE
                )
            """)
            
            # Login attempts table for security tracking
            self.db_manager.execute_query("""
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100),
                    ip_address VARCHAR(45),
                    success BOOLEAN,
                    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_agent TEXT
                )
            """)
            
            # Audit log table
            self.db_manager.execute_query("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id SERIAL PRIMARY KEY,
                    user_id VARCHAR(255),
                    action VARCHAR(100),
                    resource VARCHAR(255),
                    details TEXT,
                    ip_address VARCHAR(45),
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create default admin user if no users exist
            self._create_default_admin()
            
        except Exception as e:
            logger.error(f"Failed to initialize auth tables: {e}")

    def _create_default_admin(self):
        """Create default admin user if no users exist."""
        try:
            result = self.db_manager.execute_query("SELECT COUNT(*) as count FROM users", fetch=True) 
            
            if result and len(result) > 0 and result[0]['count'] == 0:
                admin_password = secrets.token_urlsafe(16)
                self.create_user(
                    username='admin',
                    email='admin@example.com',
                    password=admin_password,
                    role='admin'
                )
                logger.warning(f"Created default admin user with password: {admin_password}")
                logger.warning("Please change the admin password immediately!")
        except Exception as e:
            logger.error(f"Failed to create default admin user: {e}")
    
    def hash_password(self, password: str, salt: Optional[str] = None) -> tuple:
        """Hash password with salt."""
        if salt is None:
            salt = secrets.token_urlsafe(32)
        
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # iterations
        ).hex()
        
        return password_hash, salt
    
    def verify_password(self, password: str, password_hash: str, salt: str) -> bool:
        """Verify password against hash."""
        test_hash, _ = self.hash_password(password, salt)
        return secrets.compare_digest(test_hash, password_hash)
    
    def create_user(self, username: str, email: str, password: str, role: str = 'user') -> Dict[str, Any]:
        """Create a new user."""
        try:
            # Validate input
            if not username or not email or not password:
                return {'success': False, 'error': 'Username, email, and password are required'}
            
            if len(password) < 8:
                return {'success': False, 'error': 'Password must be at least 8 characters'}
            
            # Check if user already exists
            existing_user = self.db_manager.execute_query(
                "SELECT username FROM users WHERE username = %s OR email = %s",
                (username, email),
                fetch=True
            )
            
            if existing_user: 
                return {'success': False, 'error': 'Username or email already exists'}
            
            # Create user
            user_id = secrets.token_urlsafe(16)
            password_hash, salt = self.hash_password(password)
            
            # Store preferences as a JSON string
            self.db_manager.execute_query("""
                INSERT INTO users (user_id, username, email, password_hash, salt, role, preferences)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (user_id, username, email, password_hash, salt, role, json.dumps({}))) # Store empty dict as JSON string
            
            logger.info(f"Created user: {username} with role: {role}")
            return {'success': True, 'user_id': user_id}
            
        except Exception as e:
            logger.error(f"Failed to create user {username}: {e}")
            return {'success': False, 'error': 'Failed to create user'}
    
    def authenticate_user(self, username: str, password: str, ip_address: str, user_agent: str) -> Dict[str, Any]:
        """Authenticate user with username and password."""
        try:
            # Check if IP is locked out
            if self._is_ip_locked_out(ip_address):
                return {'success': False, 'error': 'Too many failed attempts. Please try again later.'}
            
            # Get user
            user_data_list = self.db_manager.execute_query( # Renamed to user_data_list to be explicit
                "SELECT * FROM users WHERE username = %s AND is_active = TRUE",
                (username,),
                fetch=True 
            )
            
            if not user_data_list: # user_data_list will now be an empty list if no user found
                self._log_login_attempt(username, ip_address, False, user_agent)
                return {'success': False, 'error': 'Invalid username or password'}
            
            user_data = user_data_list[0] # This is the sqlite3.Row object
            
            # Verify password
            if not self.verify_password(password, user_data['password_hash'], user_data['salt']):
                self._log_login_attempt(username, ip_address, False, user_agent)
                return {'success': False, 'error': 'Invalid username or password'}
            
            # Create session
            session_id = self._create_session(user_data['user_id'], ip_address, user_agent)
            
            # Update last login
            self.db_manager.execute_query(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = %s",
                (user_data['user_id'],)
            )
            
            # Log successful login
            self._log_login_attempt(username, ip_address, True, user_agent)
            self._log_audit_event(user_data['user_id'], 'login', 'session', 'User logged in', ip_address)
            
            # FIX: Properly parse preferences from JSON string
            parsed_preferences = {}
            raw_preferences = user_data['preferences']
            if raw_preferences: # Only try to parse if not None or empty string
                try:
                    parsed_preferences = json.loads(raw_preferences)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse preferences for user {user_data.get('user_id', 'unknown')}: {e}. Raw data: {raw_preferences}")
                    # Keep parsed_preferences as empty dict on error

            # Create user object, using the helper for timestamp conversion
            user = User(
                user_id=user_data['user_id'],
                username=user_data['username'],
                email=user_data['email'],
                role=user_data['role'],
                created_at=_parse_db_timestamp_to_float(user_data['created_at']) or time.time(), # Fallback to current time if parsing fails
                last_login=_parse_db_timestamp_to_float(user_data['last_login']),
                is_active=user_data['is_active'],
                preferences=parsed_preferences # Use the parsed dictionary
            )
            
            return {
                'success': True,
                'session_id': session_id,
                'user': user.to_dict()
            }
            
        except Exception as e:
            logger.error(f"Authentication failed for {username}: {e}")
            return {'success': False, 'error': 'Authentication failed'}
    
    def _create_session(self, user_id: str, ip_address: str, user_agent: str) -> str:
        """Create a new user session."""
        session_id = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(seconds=self.session_timeout)
        
        self.db_manager.execute_query("""
            INSERT INTO user_sessions (session_id, user_id, expires_at, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s)
        """, (session_id, user_id, expires_at, ip_address, user_agent))
        
        # Cache session for quick access
        session_data = {
            'user_id': user_id,
            'expires_at': expires_at.isoformat(),
            'ip_address': ip_address
        }
        self.cache_manager.set(f"session:{session_id}", session_data, self.session_timeout)
        
        return session_id
    
    def validate_session(self, session_id: str) -> Optional[str]:
        """Validate session and return user_id if valid."""
        try:
            # Check cache first
            session_data = self.cache_manager.get(f"session:{session_id}")
            
            if session_data:
                expires_at = datetime.fromisoformat(session_data['expires_at'])
                if datetime.now() < expires_at:
                    return session_data['user_id']
            
            # Check database
            session_data_list = self.db_manager.execute_query(""" # Renamed for clarity
                SELECT user_id, expires_at FROM user_sessions 
                WHERE session_id = %s AND is_active = TRUE
            """, (session_id,), fetch=True) 
            
            if session_data_list and datetime.now() < session_data_list[0]['expires_at']:
                return session_data_list[0]['user_id']
            
            return None
            
        except Exception as e:
            logger.error(f"Session validation failed: {e}")
            return None
    
    def logout_user(self, session_id: str, user_id: str, ip_address: str):
        """Logout user and invalidate session."""
        try:
            # Invalidate session in database
            self.db_manager.execute_query(
                "UPDATE user_sessions SET is_active = FALSE WHERE session_id = %s",
                (session_id,)
            )
            
            # Remove from cache
            self.cache_manager.delete(f"session:{session_id}")
            
            # Log audit event
            self._log_audit_event(user_id, 'logout', 'session', 'User logged out', ip_address)
            
            logger.info(f"User {user_id} logged out")
            
        except Exception as e:
            logger.error(f"Logout failed for user {user_id}: {e}")
    
    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        try:
            user_data_list = self.db_manager.execute_query( # Renamed for clarity
                "SELECT * FROM users WHERE user_id = %s AND is_active = TRUE",
                (user_id,),
                fetch=True 
            )
            
            if not user_data_list:
                return None
            
            user_data = user_data_list[0] # This is the sqlite3.Row object

            # FIX: Properly parse preferences from JSON string
            parsed_preferences = {}
            raw_preferences = user_data['preferences']
            if raw_preferences: # Only try to parse if not None or empty string
                try:
                    parsed_preferences = json.loads(raw_preferences)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse preferences for user {user_data.get('user_id', 'unknown')}: {e}. Raw data: {raw_preferences}")
                    # Keep parsed_preferences as empty dict on error
            
            # Create user object, using the helper for timestamp conversion
            return User(
                user_id=user_data['user_id'],
                username=user_data['username'],
                email=user_data['email'],
                role=user_data['role'],
                created_at=_parse_db_timestamp_to_float(user_data['created_at']) or time.time(), # Fallback to current time
                last_login=_parse_db_timestamp_to_float(user_data['last_login']),
                is_active=user_data['is_active'],
                preferences=parsed_preferences # Use the parsed dictionary
            )
            
        except Exception as e:
            logger.error(f"Failed to get user {user_id}: {e}")
            return None
    
    def _is_ip_locked_out(self, ip_address: str) -> bool:
        """Check if IP address is locked out due to failed login attempts."""
        try:
            cutoff_time = datetime.now() - timedelta(seconds=self.lockout_duration)
            
            failed_attempts = self.db_manager.execute_query("""
                SELECT COUNT(*) as count FROM login_attempts 
                WHERE ip_address = %s AND success = FALSE AND attempted_at > %s
            """, (ip_address, cutoff_time), fetch=True) 
            
            return failed_attempts and failed_attempts[0]['count'] >= self.max_login_attempts
            
        except Exception as e:
            logger.error(f"Failed to check IP lockout: {e}")
            return False
    
    def _log_login_attempt(self, username: str, ip_address: str, success: bool, user_agent: str):
        """Log login attempt."""
        try:
            self.db_manager.execute_query("""
                INSERT INTO login_attempts (username, ip_address, success, user_agent)
                VALUES (%s, %s, %s, %s)
            """, (username, ip_address, success, user_agent))
        except Exception as e:
            logger.error(f"Failed to log login attempt: {e}")
    
    def _log_audit_event(self, user_id: str, action: str, resource: str, details: str, ip_address: str):
        """Log audit event."""
        try:
            self.db_manager.execute_query("""
                INSERT INTO audit_log (user_id, action, resource, details, ip_address)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, action, resource, details, ip_address))
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
    
    def generate_jwt_token(self, user: User) -> str:
        """Generate JWT token for API access."""
        payload = {
            'user_id': user.user_id,
            'username': user.username,
            'role': user.role,
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def verify_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token and return payload."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def get_all_users(self) -> List[User]:
        """Get all users (admin only)."""
        try:
            # FIX: Added preferences to the SELECT query
            users_data = self.db_manager.execute_query("""
                SELECT user_id, username, email, role, created_at, last_login, is_active, preferences
                FROM users
                ORDER BY created_at DESC
            """, fetch=True) 
            
            users = []
            for user_data in users_data:
                # FIX: Properly parse preferences from JSON string for each user
                parsed_preferences = {}
                raw_preferences = user_data['preferences']
                if raw_preferences:
                    try:
                        parsed_preferences = json.loads(raw_preferences)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse preferences for user {user_data.get('user_id', 'unknown')}: {e}. Raw data: {raw_preferences}")
                        # Keep parsed_preferences as empty dict on error

                # Use the helper for timestamp conversion and parsed preferences
                user = User(
                    user_id=user_data['user_id'],
                    username=user_data['username'],
                    email=user_data['email'],
                    role=user_data['role'],
                    created_at=_parse_db_timestamp_to_float(user_data['created_at']) or time.time(),
                    last_login=_parse_db_timestamp_to_float(user_data['last_login']),
                    is_active=user_data['is_active'],
                    preferences=parsed_preferences # Use the parsed dictionary
                )
                users.append(user)
            
            return users
            
        except Exception as e:
            self._log_audit_event(None, 'get_all_users_failed', 'users', str(e), '')
            return []
    
    def delete_user(self, user_id: str) -> bool:
        """Delete a user (admin only)."""
        try:
            # First check if user exists
            user = self.get_user(user_id) 
            if not user:
                return False
            
            # Delete user sessions first
            self.db_manager.execute_query("""
                DELETE FROM user_sessions WHERE user_id = %s
            """, (user_id,))
            
            # Delete user
            result = self.db_manager.execute_query("""
                DELETE FROM users WHERE user_id = %s
            """, (user_id,))
            
            if result: 
                self._log_audit_event(None, 'user_deleted', user.username, f'User {user.username} deleted', '')
                return True
            
            return False
            
        except Exception as e:
            self._log_audit_event(None, 'delete_user_failed', str(user_id), str(e), '')
            return False
    
    def toggle_user_status(self, user_id: str) -> bool:
        """Enable/disable a user (admin only)."""
        try:
            # Get current status
            user = self.get_user(user_id) 
            if not user:
                return False
            
            new_status = not user.is_active
            
            # Update status
            result = self.db_manager.execute_query("""
                UPDATE users SET is_active = %s WHERE user_id = %s
            """, (new_status, user_id))
            
            if result: 
                action = 'user_enabled' if new_status else 'user_disabled'
                self._log_audit_event(None, action, user.username, f'User {user.username} {action}', '')
                
                # If disabling, invalidate all sessions
                if not new_status:
                    self.db_manager.execute_query("""
                        UPDATE user_sessions SET is_active = FALSE WHERE user_id = %s
                    """, (user_id,))
                
                return True
            
            return False
            
        except Exception as e:
            self._log_audit_event(None, 'toggle_user_status_failed', str(user_id), str(e), '')
            return False
    
    def update_user_password(self, user_id: str, new_password: str) -> bool:
        """Update user password (admin or self)."""
        try:
            password_hash, salt = self.hash_password(new_password)
            
            result = self.db_manager.execute_query("""
                UPDATE users SET password_hash = %s, salt = %s WHERE user_id = %s
            """, (password_hash, salt, user_id))
            
            if result: 
                # Invalidate all sessions to force re-login
                self.db_manager.execute_query("""
                    UPDATE user_sessions SET is_active = FALSE WHERE user_id = %s
                """, (user_id,))
                
                self._log_audit_event(user_id, 'password_updated', 'user_password', 'Password updated', '')
                return True
            
            return False
            
        except Exception as e:
            self._log_audit_event(user_id, 'password_update_failed', 'user_password', str(e), '')
            return False

# Authentication decorators
def login_required(f):
    """Decorator to require user login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check session
        session_id = session.get('session_id') or request.headers.get('X-Session-ID')
        
        if not session_id:
            # Check JWT token
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                if hasattr(g, 'auth_service'):
                    payload = g.auth_service.verify_jwt_token(token)
                    if payload:
                        g.current_user_id = payload['user_id']
                        g.current_user = g.auth_service.get_user(payload['user_id'])
                        return f(*args, **kwargs)
            
            return jsonify({'error': 'Authentication required'}), 401
        
        # Validate session
        if hasattr(g, 'auth_service'):
            user_id = g.auth_service.validate_session(session_id)
            if user_id:
                g.current_user_id = user_id
                g.current_user = g.auth_service.get_user(user_id)
                return f(*args, **kwargs)
        
        return jsonify({'error': 'Invalid or expired session'}), 401
    
    return decorated_function

def require_permission(permission: str):
    """Decorator to require specific permission."""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not g.current_user or not g.current_user.has_permission(permission):
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_role(role: str):
    """Decorator to require specific role."""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not g.current_user or g.current_user.role != role:
                return jsonify({'error': f'Role {role} required'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Global auth service instance
auth_service = None

def get_auth_service() -> AuthService:
    """Get the global auth service instance."""
    return auth_service

def init_auth_service(db_manager, cache_manager, config: Dict[str, Any]):
    """Initialize the global auth service."""
    global auth_service
    auth_service = AuthService(db_manager, cache_manager, config)
    return auth_service
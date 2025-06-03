"""
Security Service for EASM Application

This module provides comprehensive security features including:
- Input validation and sanitization
- Path traversal protection
- XSS prevention
- SQL injection protection
- Rate limiting integration
- Security headers management
- Authentication and authorization helpers

Author: EASM Development Team
"""

import os
import re
import html
import hashlib
import secrets
import logging
from typing import Dict, Any, Optional, List, Union
from urllib.parse import urlparse, unquote
from pathlib import Path
from functools import wraps
from flask import request, jsonify, session, g
import ipaddress
import validators
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class SecurityService:
    """Comprehensive security service for input validation and protection."""
    
    # Allowed file extensions for uploads
    ALLOWED_EXTENSIONS = {'.txt', '.csv', '.json', '.xml'}
    
    # Maximum file size (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024
    
    # Dangerous characters for path traversal
    DANGEROUS_CHARS = ['..', '~', '\\', '//', '<', '>', '|', '&', ';', '`', '$']
    
    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
        r"(--|#|/\*|\*/)",
        r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
        r"(\b(OR|AND)\s+['\"].*['\"])",
        r"(\bUNION\s+SELECT\b)",
        r"(\bINTO\s+OUTFILE\b)",
        r"(\bLOAD_FILE\b)"
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<\s*script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script\s*>",
        r"<\s*iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe\s*>",
        r"<\s*object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object\s*>",
        r"<\s*embed\b[^<]*>",
        r"<\s*link\b[^<]*>",
        r"javascript:",
        r"vbscript:",
        r"on\w+\s*=",
        r"expression\s*\(",
        r"url\s*\(",
        r"@import"
    ]
    
    def __init__(self, app_config: Dict[str, Any]):
        self.config = app_config
        self.allowed_hosts = app_config.get('ALLOWED_HOSTS', ['localhost', '127.0.0.1'])
        self.secure_cookies = app_config.get('SECURE_COOKIES', False)
        self.session_timeout = app_config.get('SESSION_TIMEOUT', 3600)
        
        # Compile regex patterns for performance
        self.sql_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.SQL_INJECTION_PATTERNS]
        self.xss_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.XSS_PATTERNS]
    
    def validate_input(self, data: Any, validation_type: str = 'general') -> Dict[str, Any]:
        """
        Validate and sanitize input data based on type.
        
        Args:
            data: Input data to validate
            validation_type: Type of validation to perform
            
        Returns:
            Dictionary with validation results and sanitized data
        """
        try:
            if data is None:
                return {'valid': True, 'sanitized': None, 'errors': []}
            
            errors = []
            
            if validation_type == 'domain':
                return self._validate_domain(data)
            elif validation_type == 'ip':
                return self._validate_ip(data)
            elif validation_type == 'url':
                return self._validate_url(data)
            elif validation_type == 'filename':
                return self._validate_filename(data)
            elif validation_type == 'path':
                return self._validate_path(data)
            elif validation_type == 'text':
                return self._validate_text(data)
            elif validation_type == 'email':
                return self._validate_email(data)
            else:
                return self._validate_general(data)
                
        except Exception as e:
            logger.error(f"Input validation error: {e}")
            return {
                'valid': False,
                'sanitized': None,
                'errors': [f"Validation error: {str(e)}"]
            }
    
    def _validate_domain(self, domain: str) -> Dict[str, Any]:
        """Validate domain name."""
        if not isinstance(domain, str):
            return {'valid': False, 'sanitized': None, 'errors': ['Domain must be a string']}
        
        # Sanitize
        domain = domain.strip().lower()
        
        # Basic format validation
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$', domain):
            return {'valid': False, 'sanitized': domain, 'errors': ['Invalid domain format']}
        
        # Length validation
        if len(domain) > 253:
            return {'valid': False, 'sanitized': domain, 'errors': ['Domain too long']}
        
        # Check for dangerous patterns
        if any(char in domain for char in ['<', '>', '"', "'"]):
            return {'valid': False, 'sanitized': domain, 'errors': ['Domain contains dangerous characters']}
        
        return {'valid': True, 'sanitized': domain, 'errors': []}
    
    def _validate_ip(self, ip: str) -> Dict[str, Any]:
        """Validate IP address."""
        if not isinstance(ip, str):
            return {'valid': False, 'sanitized': None, 'errors': ['IP must be a string']}
        
        ip = ip.strip()
        
        try:
            # Validate IPv4 or IPv6
            ipaddress.ip_address(ip)
            
            # Check for private/reserved ranges if needed
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private and not self.config.get('ALLOW_PRIVATE_IPS', False):
                return {'valid': False, 'sanitized': ip, 'errors': ['Private IP addresses not allowed']}
            
            return {'valid': True, 'sanitized': ip, 'errors': []}
            
        except ValueError:
            return {'valid': False, 'sanitized': ip, 'errors': ['Invalid IP address format']}
    
    def _validate_url(self, url: str) -> Dict[str, Any]:
        """Validate URL."""
        if not isinstance(url, str):
            return {'valid': False, 'sanitized': None, 'errors': ['URL must be a string']}
        
        url = url.strip()
        
        # Basic URL validation
        if not validators.url(url):
            return {'valid': False, 'sanitized': url, 'errors': ['Invalid URL format']}
        
        # Parse URL
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in ['http', 'https']:
            return {'valid': False, 'sanitized': url, 'errors': ['Only HTTP and HTTPS schemes allowed']}
        
        # Check for XSS in URL
        xss_result = self._check_xss(url)
        if not xss_result['safe']:
            return {'valid': False, 'sanitized': url, 'errors': ['URL contains potentially malicious content']}
        
        return {'valid': True, 'sanitized': url, 'errors': []}
    
    def _validate_filename(self, filename: str) -> Dict[str, Any]:
        """Validate filename for uploads."""
        if not isinstance(filename, str):
            return {'valid': False, 'sanitized': None, 'errors': ['Filename must be a string']}
        
        # Sanitize filename
        filename = os.path.basename(filename).strip()
        
        # Check for empty filename
        if not filename:
            return {'valid': False, 'sanitized': filename, 'errors': ['Filename cannot be empty']}
        
        # Check for dangerous patterns
        if any(char in filename for char in self.DANGEROUS_CHARS):
            return {'valid': False, 'sanitized': filename, 'errors': ['Filename contains dangerous characters']}
        
        # Check file extension
        file_ext = Path(filename).suffix.lower()
        if file_ext not in self.ALLOWED_EXTENSIONS:
            return {
                'valid': False, 
                'sanitized': filename, 
                'errors': [f'File extension {file_ext} not allowed. Allowed: {", ".join(self.ALLOWED_EXTENSIONS)}']
            }
        
        # Length check
        if len(filename) > 255:
            return {'valid': False, 'sanitized': filename, 'errors': ['Filename too long']}
        
        return {'valid': True, 'sanitized': filename, 'errors': []}
    
    def _validate_path(self, path: str) -> Dict[str, Any]:
        """Validate file path for path traversal attacks."""
        if not isinstance(path, str):
            return {'valid': False, 'sanitized': None, 'errors': ['Path must be a string']}
        
        # Normalize path
        path = os.path.normpath(path)
        
        # Check for path traversal attempts
        if '..' in path or path.startswith('/'):
            return {'valid': False, 'sanitized': path, 'errors': ['Path traversal attempt detected']}
        
        # Check for dangerous characters
        if any(char in path for char in ['<', '>', '|', '&', ';', '`', '$']):
            return {'valid': False, 'sanitized': path, 'errors': ['Path contains dangerous characters']}
        
        return {'valid': True, 'sanitized': path, 'errors': []}
    
    def _validate_text(self, text: str) -> Dict[str, Any]:
        """Validate and sanitize text input."""
        if not isinstance(text, str):
            return {'valid': False, 'sanitized': None, 'errors': ['Text must be a string']}
        
        errors = []
        
        # Check for SQL injection
        sql_result = self._check_sql_injection(text)
        if not sql_result['safe']:
            errors.append('Text contains potential SQL injection patterns')
        
        # Check for XSS
        xss_result = self._check_xss(text)
        if not xss_result['safe']:
            errors.append('Text contains potential XSS patterns')
        
        # Sanitize HTML
        sanitized = html.escape(text)
        
        # Length check
        if len(text) > 10000:  # 10KB limit
            errors.append('Text too long')
        
        return {
            'valid': len(errors) == 0,
            'sanitized': sanitized,
            'errors': errors
        }
    
    def _validate_email(self, email: str) -> Dict[str, Any]:
        """Validate email address."""
        if not isinstance(email, str):
            return {'valid': False, 'sanitized': None, 'errors': ['Email must be a string']}
        
        email = email.strip().lower()
        
        # Basic email validation
        if not validators.email(email):
            return {'valid': False, 'sanitized': email, 'errors': ['Invalid email format']}
        
        return {'valid': True, 'sanitized': email, 'errors': []}
    
    def _validate_general(self, data: Any) -> Dict[str, Any]:
        """General validation for any input."""
        if isinstance(data, str):
            return self._validate_text(data)
        elif isinstance(data, (int, float)):
            return {'valid': True, 'sanitized': data, 'errors': []}
        elif isinstance(data, (list, dict)):
            return {'valid': True, 'sanitized': data, 'errors': []}
        else:
            return {'valid': False, 'sanitized': None, 'errors': ['Unsupported data type']}
    
    def _check_sql_injection(self, text: str) -> Dict[str, Any]:
        """Check for SQL injection patterns."""
        for pattern in self.sql_patterns:
            if pattern.search(text):
                return {
                    'safe': False,
                    'pattern_found': pattern.pattern,
                    'text_snippet': text[:100]
                }
        
        return {'safe': True}
    
    def _check_xss(self, text: str) -> Dict[str, Any]:
        """Check for XSS patterns."""
        for pattern in self.xss_patterns:
            if pattern.search(text):
                return {
                    'safe': False,
                    'pattern_found': pattern.pattern,
                    'text_snippet': text[:100]
                }
        
        return {'safe': True}
    
    def validate_file_upload(self, file_stream, filename: str) -> Dict[str, Any]:
        """Validate file upload."""
        errors = []
        
        # Validate filename
        filename_result = self.validate_input(filename, 'filename')
        if not filename_result['valid']:
            errors.extend(filename_result['errors'])
        
        # Check file size
        if hasattr(file_stream, 'content_length'):
            if file_stream.content_length > self.MAX_FILE_SIZE:
                errors.append(f'File too large. Maximum size: {self.MAX_FILE_SIZE / (1024*1024):.1f}MB')
        
        # Read file content for validation (first 1KB)
        try:
            file_stream.seek(0)
            content_sample = file_stream.read(1024)
            file_stream.seek(0)
            
            # Check for binary content in text files
            if filename.endswith(('.txt', '.csv', '.json', '.xml')):
                try:
                    content_sample.decode('utf-8')
                except UnicodeDecodeError:
                    errors.append('File contains binary content but has text extension')
            
        except Exception as e:
            errors.append(f'Error reading file: {str(e)}')
        
        return {
            'valid': len(errors) == 0,
            'filename': filename_result.get('sanitized', filename),
            'errors': errors
        }
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate a secure random token."""
        return secrets.token_urlsafe(length)
    
    def hash_password(self, password: str, salt: Optional[str] = None) -> Dict[str, str]:
        """Hash password with salt."""
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Use PBKDF2 with SHA-256
        password_hash = hashlib.pbkdf2_hmac('sha256', 
                                          password.encode('utf-8'), 
                                          salt.encode('utf-8'), 
                                          100000)  # 100k iterations
        
        return {
            'hash': password_hash.hex(),
            'salt': salt
        }
    
    def verify_password(self, password: str, stored_hash: str, salt: str) -> bool:
        """Verify password against stored hash."""
        password_hash = hashlib.pbkdf2_hmac('sha256',
                                          password.encode('utf-8'),
                                          salt.encode('utf-8'),
                                          100000)
        return password_hash.hex() == stored_hash
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers for HTTP responses."""
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }
    
    def is_safe_redirect(self, url: str) -> bool:
        """Check if redirect URL is safe."""
        if not url:
            return False
        
        # Only allow relative URLs or URLs to allowed hosts
        parsed = urlparse(url)
        
        # Relative URL is safe
        if not parsed.netloc:
            return True
        
        # Check if host is in allowed list
        return parsed.netloc in self.allowed_hosts

# Security decorators
def require_valid_input(validation_type: str = 'general'):
    """Decorator to validate input parameters."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            security_service = getattr(g, 'security_service', None)
            if not security_service:
                return jsonify({'error': 'Security service not available'}), 500
            
            # Validate JSON data if present
            if request.is_json:
                data = request.get_json()
                for key, value in data.items():
                    result = security_service.validate_input(value, validation_type)
                    if not result['valid']:
                        return jsonify({
                            'error': f'Invalid input for {key}',
                            'details': result['errors']
                        }), 400
            
            # Validate form data
            for key, value in request.form.items():
                result = security_service.validate_input(value, validation_type)
                if not result['valid']:
                    return jsonify({
                        'error': f'Invalid input for {key}',
                        'details': result['errors']
                    }), 400
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_csrf_token():
    """Decorator to require CSRF token for POST requests."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method == 'POST':
                token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
                expected_token = session.get('csrf_token')
                
                if not token or not expected_token or token != expected_token:
                    return jsonify({'error': 'CSRF token validation failed'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_host_validation():
    """Decorator to validate request host."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            security_service = getattr(g, 'security_service', None)
            if not security_service:
                return jsonify({'error': 'Security service not available'}), 500
            
            host = request.headers.get('Host', '').split(':')[0]  # Remove port
            if host not in security_service.allowed_hosts:
                logger.warning(f"Request from unauthorized host: {host}")
                return jsonify({'error': 'Unauthorized host'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

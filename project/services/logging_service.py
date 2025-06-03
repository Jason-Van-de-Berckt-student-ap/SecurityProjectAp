"""
Comprehensive Logging and Audit Service for EASM Application.

This service provides structured logging, audit trails, performance monitoring,
and security event tracking with different log levels and output formats.
"""
import logging
import json
import time
import os
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass, asdict
from functools import wraps
import psutil
import traceback
from flask import request, g, session # Assuming Flask is used based on 'request', 'g', 'session'

class LogLevel(Enum):
    """Log levels for different types of events."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class EventType(Enum):
    """Types of events to log."""
    USER_ACTION = "user_action"
    SYSTEM_EVENT = "system_event"
    SECURITY_EVENT = "security_event"
    PERFORMANCE_EVENT = "performance_event"
    ERROR_EVENT = "error_event"
    AUDIT_EVENT = "audit_event"

@dataclass
class LogEvent:
    """Structured log event."""
    timestamp: float
    level: str
    event_type: str
    message: str
    user_id: Optional[str] = None
    username: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    domain: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    duration: Optional[float] = None
    status_code: Optional[int] = None
    error_details: Optional[Dict] = None
    metadata: Optional[Dict] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)

class LoggingService:
    """Comprehensive logging and audit service."""

    def __init__(self, db_manager, cache_manager, config: Dict[str, Any]):
        self.db_manager = db_manager
        self.cache_manager = cache_manager
        self.config = config

        # Configuration
        self.log_level = getattr(logging, config.get('LOG_LEVEL', 'INFO').upper())
        self.log_to_file = config.get('LOG_TO_FILE', True)
        self.log_to_db = config.get('LOG_TO_DB', True)
        self.log_to_console = config.get('LOG_TO_CONSOLE', True)
        self.log_retention_days = config.get('LOG_RETENTION_DAYS', 30)
        self.performance_threshold = config.get('PERFORMANCE_THRESHOLD', 5.0)

        # Log file paths
        self.log_dir = config.get('LOG_DIRECTORY', 'logs')
        os.makedirs(self.log_dir, exist_ok=True)

        # Thread-local storage for request context (usually for web frameworks like Flask)
        self.local = threading.local()

        # Initialize loggers
        self._init_loggers()

        # Initialize database tables
        self._init_log_tables()

        # Start background cleanup task
        self._start_cleanup_task()

    def _init_loggers(self):
        """Initialize different loggers for various purposes."""
        # Main application logger
        self.app_logger = logging.getLogger('easm.app')
        self.app_logger.setLevel(self.log_level)
        self.app_logger.propagate = False # Prevent double logging if root logger is also configured

        # Security logger
        self.security_logger = logging.getLogger('easm.security')
        self.security_logger.setLevel(logging.INFO)
        self.security_logger.propagate = False

        # Performance logger
        self.performance_logger = logging.getLogger('easm.performance')
        self.performance_logger.setLevel(logging.INFO)
        self.performance_logger.propagate = False

        # Audit logger
        self.audit_logger = logging.getLogger('easm.audit')
        self.audit_logger.setLevel(logging.INFO)
        self.audit_logger.propagate = False

        # Error logger
        self.error_logger = logging.getLogger('easm.error')
        self.error_logger.setLevel(logging.ERROR)
        self.error_logger.propagate = False

        # Configure handlers
        self._configure_handlers()

    def _configure_handlers(self):
        """Configure log handlers for different output destinations."""
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # NOTE: Original code had a 'json_formatter' but it was identical to 'formatter'
        # and not used. If JSON logging is desired, a custom formatter would be needed.
        # For now, keeping the standard formatter.

        # Console handler
        if self.log_to_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.app_logger.addHandler(console_handler)
            self.security_logger.addHandler(console_handler) # Add to other loggers if desired
            self.performance_logger.addHandler(console_handler)
            self.audit_logger.addHandler(console_handler)
            self.error_logger.addHandler(console_handler)


        # File handlers
        if self.log_to_file:
            # Main app log
            app_handler = logging.FileHandler(
                os.path.join(self.log_dir, 'app.log')
            )
            app_handler.setFormatter(formatter)
            self.app_logger.addHandler(app_handler)

            # Security log
            security_handler = logging.FileHandler(
                os.path.join(self.log_dir, 'security.log')
            )
            security_handler.setFormatter(formatter)
            self.security_logger.addHandler(security_handler)

            # Performance log
            performance_handler = logging.FileHandler(
                os.path.join(self.log_dir, 'performance.log')
            )
            performance_handler.setFormatter(formatter)
            self.performance_logger.addHandler(performance_handler)

            # Audit log
            audit_handler = logging.FileHandler(
                os.path.join(self.log_dir, 'audit.log')
            )
            audit_handler.setFormatter(formatter)
            self.audit_logger.addHandler(audit_handler)

            # Error log
            error_handler = logging.FileHandler(
                os.path.join(self.log_dir, 'error.log')
            )
            error_handler.setFormatter(formatter)
            self.error_logger.addHandler(error_handler)

    def _init_log_tables(self):
        """Initialize logging database tables."""
        if not self.log_to_db:
            self.app_logger.info("Database logging is disabled in config.")
            return

        try:
            # Main log events table
            self.db_manager.execute_query("""
                CREATE TABLE IF NOT EXISTS log_events (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    level VARCHAR(20),
                    event_type VARCHAR(50),
                    message TEXT,
                    user_id VARCHAR(255),
                    username VARCHAR(100),
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    request_id VARCHAR(255),
                    session_id VARCHAR(255),
                    domain VARCHAR(255),
                    action VARCHAR(100),
                    resource VARCHAR(255),
                    duration FLOAT,
                    status_code INTEGER,
                    error_details TEXT,
                    metadata TEXT
                )
            """)

            # Performance metrics table
            self.db_manager.execute_query("""
                CREATE TABLE IF NOT EXISTS performance_metrics (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metric_name VARCHAR(100),
                    metric_value FLOAT,
                    unit VARCHAR(20),
                    context VARCHAR(255),
                    metadata TEXT
                )
            """)

            # System health table
            self.db_manager.execute_query("""
                CREATE TABLE IF NOT EXISTS system_health (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    cpu_usage FLOAT,
                    memory_usage FLOAT,
                    disk_usage FLOAT,
                    active_connections INTEGER,
                    queue_size INTEGER,
                    response_time FLOAT,
                    error_rate FLOAT
                )
            """)
            self.app_logger.info("Logging database tables initialized successfully.")

        except Exception as e:
            self.app_logger.error(f"Failed to initialize log tables: {e}", exc_info=True)

    def _start_cleanup_task(self):
        """Start background task for log cleanup."""
        if not self.log_to_db:
            self.app_logger.info("DB logging disabled, skipping cleanup task startup.")
            return

        def cleanup_old_logs():
            try:
                cutoff_date = datetime.now() - timedelta(days=self.log_retention_days)

                # Clean up old log events
                deleted_events = self.db_manager.execute_query(
                    "DELETE FROM log_events WHERE timestamp < %s RETURNING id",
                    (cutoff_date,)
                )
                self.app_logger.info(f"Cleaned up {len(deleted_events)} old log_events.")


                # Clean up old performance metrics
                deleted_perf = self.db_manager.execute_query(
                    "DELETE FROM performance_metrics WHERE timestamp < %s RETURNING id",
                    (cutoff_date,)
                )
                self.app_logger.info(f"Cleaned up {len(deleted_perf)} old performance_metrics.")


                # Clean up old system health records
                deleted_health = self.db_manager.execute_query(
                    "DELETE FROM system_health WHERE timestamp < %s RETURNING id",
                    (cutoff_date,)
                )
                self.app_logger.info(f"Cleaned up {len(deleted_health)} old system_health records.")


                self.app_logger.info(f"Log cleanup completed for records older than {cutoff_date}.")

            except Exception as e:
                self.app_logger.error(f"Log cleanup failed: {e}", exc_info=True)
            finally:
                # Reschedule the timer
                timer = threading.Timer(86400, cleanup_old_logs)  # 24 hours
                timer.daemon = True
                timer.start()

        # Start the initial timer
        # Adding a short delay to ensure DB tables are created before first cleanup attempt
        initial_delay = 3600 # 1 hour, or could be 60 seconds for faster testing
        timer = threading.Timer(initial_delay, cleanup_old_logs)
        timer.daemon = True # Allow program to exit even if timer is running
        timer.start()
        self.app_logger.info(f"Log cleanup task scheduled to run every 24 hours, starting in {initial_delay} seconds.")


    def log_event(self, level: LogLevel, event_type: EventType, message: str, **kwargs):
        """Log a structured event."""
        try:
            # Get request context
            request_context = self._get_request_context()

            # Merge provided kwargs with request context, preferring kwargs in case of conflict
            merged_kwargs = {**request_context, **kwargs}

            # Create log event
            event = LogEvent(
                timestamp=time.time(),
                level=level.value,
                event_type=event_type.value,
                message=message,
                **merged_kwargs
            )

            # Log to appropriate Python logger
            logger = self._get_logger_by_type(event_type)
            log_method = getattr(logger, level.value.lower())
            log_method(f"[{event_type.value}] {message}")

            # Store in database
            if self.log_to_db:
                self._store_log_event(event)

            # Cache recent events for dashboard
            if self.cache_manager: # Ensure cache_manager is provided and initialized
                self._cache_recent_event(event)

        except Exception as e:
            # Fallback logging to prevent log failures from breaking the app
            self.app_logger.critical(f"CRITICAL: Logging system experienced an error: {e}", exc_info=True)

    def _get_request_context(self) -> Dict[str, Any]:
        """Get current request context for logging."""
        context = {}
        # Use a try-except block to gracefully handle situations where Flask context
        # (request, g, session) is not available (e.g., background tasks, scripts).
        try:
            # Check if Flask's request context is active
            if request:
                context['ip_address'] = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
                context['user_agent'] = request.headers.get('User-Agent', '')
                context['request_id'] = getattr(g, 'request_id', None) # Assumes request_id is set on Flask's g object

            if hasattr(g, 'current_user') and g.current_user:
                # Assumes g.current_user is an object with user_id and username attributes
                context['user_id'] = getattr(g.current_user, 'id', None) # Use 'id' for common user ID column
                context['username'] = getattr(g.current_user, 'username', None)

            if session:
                context['session_id'] = session.get('session_id')

        except RuntimeError as e:
            # This specific error usually means "outside of request context"
            # self.app_logger.debug(f"Not in Flask request context for logging: {e}")
            pass
        except Exception as e:
            # Catch any other unexpected errors when accessing Flask context
            self.app_logger.warning(f"Error getting request context for logging: {e}")

        return context

    def _get_logger_by_type(self, event_type: EventType) -> logging.Logger:
        """Get appropriate logger based on event type."""
        logger_map = {
            EventType.SECURITY_EVENT: self.security_logger,
            EventType.PERFORMANCE_EVENT: self.performance_logger,
            EventType.AUDIT_EVENT: self.audit_logger,
            EventType.ERROR_EVENT: self.error_logger,
            # Fallback to app_logger for others or if specific logger not found
        }
        return logger_map.get(event_type, self.app_logger)

    def _store_log_event(self, event: LogEvent):
        """Store log event in database."""
        if not self.log_to_db:
            return

        try:
            # Convert timestamp float to datetime object for DB storage
            event_timestamp_dt = datetime.fromtimestamp(event.timestamp)

            # Ensure error_details and metadata are JSON strings or None
            error_details_json = json.dumps(event.error_details) if event.error_details else None
            metadata_json = json.dumps(event.metadata) if event.metadata else None

            self.db_manager.execute_query("""
                INSERT INTO log_events (
                    timestamp, level, event_type, message, user_id, username,
                    ip_address, user_agent, request_id, session_id, domain,
                    action, resource, duration, status_code, error_details, metadata
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                event_timestamp_dt,
                event.level, event.event_type, event.message, event.user_id,
                event.username, event.ip_address, event.user_agent, event.request_id,
                event.session_id, event.domain, event.action, event.resource,
                event.duration, event.status_code,
                error_details_json,
                metadata_json
            ))
        except Exception as e:
            self.app_logger.error(f"Failed to store log event to database: {e}", exc_info=True)

    def _cache_recent_event(self, event: LogEvent):
        """Cache recent events for dashboard display."""
        if not self.cache_manager:
            return

        try:
            # Store recent events in cache for quick access
            recent_events_key = f"recent_events:{event.event_type}"
            # Use a short TTL for recent events, or a list that gets trimmed
            recent_events = self.cache_manager.get(recent_events_key) or []

            # Add new event and keep only last 100
            # Convert timestamp to a more readable format for cached display if desired
            event_dict = event.to_dict()
            event_dict['timestamp_iso'] = datetime.fromtimestamp(event.timestamp).isoformat()
            recent_events.insert(0, event_dict)
            recent_events = recent_events[:100]

            self.cache_manager.set(recent_events_key, recent_events, 3600)  # Cache for 1 hour

        except Exception as e:
            self.app_logger.error(f"Failed to cache recent event: {e}", exc_info=True)

    def log_user_action(self, action: str, resource: str = None, domain: str = None, **kwargs):
        """Log user action."""
        self.log_event(
            LogLevel.INFO,
            EventType.USER_ACTION,
            f"User action: {action}",
            action=action,
            resource=resource,
            domain=domain,
            **kwargs
        )

    def log_security_event(self, message: str, severity: str = "medium", **kwargs):
        """Log security event."""
        level = LogLevel.WARNING if severity == "medium" else LogLevel.CRITICAL
        self.log_event(
            level,
            EventType.SECURITY_EVENT,
            message,
            metadata={'severity': severity, **kwargs.pop('metadata', {})}, # Merge metadata
            **kwargs
        )

    def log_performance_event(self, operation: str, duration: float, **kwargs):
        """Log performance event."""
        level = LogLevel.WARNING if duration > self.performance_threshold else LogLevel.INFO
        self.log_event(
            level,
            EventType.PERFORMANCE_EVENT,
            f"Performance: {operation} took {duration:.2f}s",
            action=operation,
            duration=duration,
            **kwargs
        )

    def log_error(self, error: Exception, context: str = None, **kwargs):
        """Log error with full traceback."""
        error_details = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'traceback': traceback.format_exc(),
            'context': context
        }

        self.log_event(
            LogLevel.ERROR,
            EventType.ERROR_EVENT,
            f"Error in {context}: {str(error)}" if context else str(error),
            error_details=error_details,
            **kwargs
        )

    def log_audit_event(self, action: str, resource: str, details: str = None, **kwargs):
        """Log audit event."""
        metadata_dict = {'details': details} if details else {}
        if 'metadata' in kwargs and isinstance(kwargs['metadata'], dict):
            metadata_dict.update(kwargs.pop('metadata')) # Merge any additional metadata

        self.log_event(
            LogLevel.INFO,
            EventType.AUDIT_EVENT,
            f"Audit: {action} on {resource}",
            action=action,
            resource=resource,
            metadata=metadata_dict,
            **kwargs
        )

    def log_system_health(self):
        """Log current system health metrics."""
        if not self.log_to_db:
            return

        try:
            # Get system metrics
            cpu_usage = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            # Placeholder for active connections, queue size, response time, error rate
            # These would need to be integrated from other parts of the EASM application
            active_connections = 0
            queue_size = 0
            response_time = 0.0
            error_rate = 0.0

            # Store in database
            self.db_manager.execute_query("""
                INSERT INTO system_health (
                    cpu_usage, memory_usage, disk_usage, active_connections,
                    queue_size, response_time, error_rate, timestamp
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                cpu_usage,
                memory.percent,
                disk.percent,
                active_connections,
                queue_size,
                response_time,
                error_rate,
                datetime.now() # Explicitly add timestamp
            ))

            # Log if thresholds exceeded using log_event for consistent logging
            if cpu_usage > 80:
                self.log_event(
                    LogLevel.WARNING,
                    EventType.SYSTEM_EVENT,
                    f"High CPU usage: {cpu_usage}%",
                    metadata={'metric': 'cpu_usage', 'value': cpu_usage}
                )

            if memory.percent > 80:
                self.log_event(
                    LogLevel.WARNING,
                    EventType.SYSTEM_EVENT,
                    f"High memory usage: {memory.percent}%",
                    metadata={'metric': 'memory_usage', 'value': memory.percent}
                )

            if disk.percent > 80:
                self.log_event(
                    LogLevel.WARNING,
                    EventType.SYSTEM_EVENT,
                    f"High disk usage: {disk.percent}%",
                    metadata={'metric': 'disk_usage', 'value': disk.percent}
                )

        except Exception as e:
            self.log_error(e, "system_health_monitoring")

    def get_recent_events(self, event_type: str = None, limit: int = 100) -> List[Dict]:
        """Get recent events from cache."""
        if not self.cache_manager:
            self.app_logger.warning("Cache manager not available for get_recent_events.")
            return []

        try:
            if event_type:
                events = self.cache_manager.get(f"recent_events:{event_type}") or []
            else:
                # Get all recent events across types
                events = []
                for et_enum in EventType: # Iterate through the Enum members
                    type_events = self.cache_manager.get(f"recent_events:{et_enum.value}") or []
                    events.extend(type_events)

                # Sort by timestamp
                events.sort(key=lambda x: x.get('timestamp', 0), reverse=True)

            return events[:limit]

        except Exception as e:
            self.log_error(e, "get_recent_events")
            return []

    def get_event_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get event statistics for the specified time period from DB."""
        if not self.log_to_db:
            return {'error': 'DB logging disabled'}
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)

            # Get event counts by type and level
            event_counts = self.db_manager.execute_query("""
                SELECT event_type, level, COUNT(*) as count
                FROM log_events
                WHERE timestamp > %s
                GROUP BY event_type, level
                ORDER BY count DESC
            """, (cutoff_time,))

            # Get error count
            error_count_results = self.db_manager.execute_query("""
                SELECT COUNT(*) as count
                FROM log_events
                WHERE timestamp > %s AND level IN ('ERROR', 'CRITICAL')
            """, (cutoff_time,))
            error_count = error_count_results[0]['count'] if error_count_results else 0

            # Get total count
            total_count_results = self.db_manager.execute_query("""
                SELECT COUNT(*) as count
                FROM log_events
                WHERE timestamp > %s
            """, (cutoff_time,))
            total_count = total_count_results[0]['count'] if total_count_results else 0

            error_rate = 0.0
            if total_count > 0:
                error_rate = (error_count / total_count) * 100.0

            return {
                'event_counts': event_counts,
                'error_rate': error_rate,
                'total_events': total_count,
                'time_period_hours': hours
            }

        except Exception as e:
            self.log_error(e, "get_event_statistics")
            return {'error': str(e)}

    def get_performance_summary(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get performance summary for dashboard."""
        if not self.log_to_db:
            return []
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)

            results = self.db_manager.execute_query("""
                SELECT
                    action as name,
                    AVG(duration) as avg_duration,
                    COUNT(*) as total_calls,
                    MAX(duration) as max_duration,
                    MIN(duration) as min_duration
                FROM log_events
                WHERE timestamp > %s AND duration IS NOT NULL AND event_type = %s
                GROUP BY action
                ORDER BY avg_duration DESC
                LIMIT 10
            """, (cutoff_time, EventType.PERFORMANCE_EVENT.value)) # Filter for performance events

            return results or []

        except Exception as e:
            self.log_error(e, "get_performance_summary")
            return []

    def get_recent_logs(self, log_type: Optional[str] = None, limit: int = 20, **filters) -> List[Dict[str, Any]]:
        """Get recent logs with optional filtering from DB."""
        if not self.log_to_db:
            return []
        try:
            conditions = ["1=1"] # Start with a true condition
            params: List[Union[str, int, datetime]] = [] # Explicitly type params for clarity

            if log_type:
                conditions.append("event_type = %s")
                params.append(log_type)

            # Example: Handle 'level' filter as well
            if 'level' in filters and filters['level']:
                conditions.append("level = %s")
                params.append(filters['level'].upper()) # Ensure level is uppercase for Enum matching

            if 'severity' in filters and filters['severity']:
                # Note: JSON_EXTRACT syntax might vary slightly by DB (e.g., PostgreSQL needs '->>' operator)
                # Assuming a JSON_EXTRACT or equivalent function is available that returns text
                conditions.append("metadata->>'severity' = %s") # PostgreSQL JSON operator example
                params.append(filters['severity'])

            if 'time_range' in filters and filters['time_range']:
                hours_map = {'1h': 1, '24h': 24, '7d': 168, '30d': 720}
                hours = hours_map.get(filters['time_range'], 24)
                cutoff_time = datetime.now() - timedelta(hours=hours)
                conditions.append("timestamp > %s")
                params.append(cutoff_time)

            if 'search_query' in filters and filters['search_query']:
                search_term = f"%{filters['search_query']}%"
                conditions.append("(message ILIKE %s OR username ILIKE %s OR ip_address ILIKE %s OR resource ILIKE %s)")
                params.extend([search_term, search_term, search_term, search_term])


            query = f"""
                SELECT
                    timestamp, event_type as log_type, level, username,
                    action, resource, message, ip_address,
                    metadata->>'severity' as severity, -- PostgreSQL specific JSON field access
                    metadata->>'details' as details,     -- PostgreSQL specific JSON field access
                    error_details,
                    duration,
                    status_code
                FROM log_events
                WHERE {' AND '.join(conditions)}
                ORDER BY timestamp DESC
                LIMIT %s
            """
            params.append(limit)

            results = self.db_manager.execute_query(query, params)
            return results or []

        except Exception as e:
            self.log_error(e, "get_recent_logs_from_db")
            return []

    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get scan statistics for dashboard."""
        if not self.log_to_db:
            return {'error': 'DB logging disabled', 'scans_today': 0, 'avg_scan_time': 0, 'success_rate': 100, 'active_tasks': 0}
        try:
            today = datetime.now().date()

            # Scans today
            scans_today_results = self.db_manager.execute_query("""
                SELECT COUNT(*) as count
                FROM log_events
                WHERE DATE(timestamp) = %s
                AND event_type = %s AND action LIKE '%scan%'
            """, (today, EventType.USER_ACTION.value)) # Assuming scan actions are user actions
            scans_today = scans_today_results[0]['count'] if scans_today_results else 0

            # Average scan time for last 7 days (performance events)
            avg_time_results = self.db_manager.execute_query("""
                SELECT AVG(duration) as avg_duration
                FROM log_events
                WHERE event_type = %s AND action LIKE '%scan%'
                AND duration IS NOT NULL
                AND timestamp > %s
            """, (EventType.PERFORMANCE_EVENT.value, datetime.now() - timedelta(days=7)))
            avg_scan_time = avg_time_results[0]['avg_duration'] if avg_time_results and avg_time_results[0]['avg_duration'] else 0.0

            # Success rate for scans (last 7 days, excluding ERROR/CRITICAL level scan events)
            success_rate_results = self.db_manager.execute_query("""
                SELECT
                    (SUM(CASE WHEN level NOT IN ('ERROR', 'CRITICAL') THEN 1 ELSE 0 END) * 100.0 / COUNT(*)) as success_rate
                FROM log_events
                WHERE (event_type = %s OR event_type = %s) AND action LIKE '%scan%'
                AND timestamp > %s
            """, (EventType.USER_ACTION.value, EventType.PERFORMANCE_EVENT.value, datetime.now() - timedelta(days=7)))
            success_rate = success_rate_results[0]['success_rate'] if success_rate_results and success_rate_results[0]['success_rate'] else 100.0

            return {
                'scans_today': scans_today,
                'avg_scan_time': avg_scan_time,
                'success_rate': success_rate,
                'active_tasks': 0  # This would need to be implemented with a dedicated task manager
            }

        except Exception as e:
            self.log_error(e, "get_scan_statistics")
            return {
                'scans_today': 0,
                'avg_scan_time': 0.0,
                'success_rate': 100.0,
                'active_tasks': 0
            }


# Decorators for automatic logging
def log_performance(operation_name: Optional[str] = None):
    """Decorator to log function performance."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            # Default operation name to module.function_name if not provided
            op_name = operation_name or f"{func.__module__}.{func.__name__}"

            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time

                # Check if logging_service is initialized and accessible
                if hasattr(g, 'logging_service') and g.logging_service:
                    g.logging_service.log_performance_event(op_name, duration)
                else:
                    # Fallback if logging_service isn't in g (e.g., direct function call, not Flask request)
                    # This implies you might need a way to get the logging_service instance
                    # outside of Flask's g object if this decorator is used broadly.
                    # For now, print a warning or fallback to standard logging.
                    logging.getLogger(__name__).debug(f"LoggingService not found in g. Performance of {op_name} took {duration:.2f}s.")
                return result

            except Exception as e:
                duration = time.time() - start_time
                if hasattr(g, 'logging_service') and g.logging_service:
                    g.logging_service.log_error(e, op_name)
                    g.logging_service.log_performance_event(f"{op_name}_failed", duration)
                else:
                    logging.getLogger(__name__).exception(f"Error in {op_name} and LoggingService not available.")
                raise # Re-raise the exception after logging
        return wrapper
    return decorator

def log_user_action(action: str, resource: Optional[str] = None):
    """Decorator to log user actions."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)

                if hasattr(g, 'logging_service') and g.logging_service:
                    g.logging_service.log_user_action(action, resource)
                else:
                    logging.getLogger(__name__).debug(f"LoggingService not found in g. User action: {action} on {resource}.")
                return result

            except Exception as e:
                if hasattr(g, 'logging_service') and g.logging_service:
                    g.logging_service.log_error(e, f"user_action_{action}")
                else:
                    logging.getLogger(__name__).exception(f"Error during user action {action} and LoggingService not available.")
                raise # Re-raise the exception after logging
        return wrapper
    return decorator

# Global logging service instance
logging_service: Optional[LoggingService] = None # Initialize as None, specify type hint

def get_logging_service() -> LoggingService:
    """Get the global logging service instance. Raises RuntimeError if not initialized."""
    if logging_service is None:
        raise RuntimeError("LoggingService has not been initialized. Call init_logging_service first.")
    return logging_service

def init_logging_service(db_manager: Any, cache_manager: Any, config: Dict[str, Any]) -> LoggingService:
    """Initialize the global logging service."""
    global logging_service
    if logging_service is not None:
        logging.getLogger(__name__).warning("LoggingService already initialized. Re-initializing.")
    logging_service = LoggingService(db_manager, cache_manager, config)
    return logging_service
"""
Health Check Service for EASM Application

This module provides comprehensive health checking capabilities for all application components:
- Database connectivity and performance
- Redis cache availability and performance
- Background task system status
- System resource monitoring
- Service dependencies validation

Author: EASM Development Team
"""

import time
import psutil
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from flask import Blueprint, jsonify, request
from concurrent.futures import ThreadPoolExecutor, as_completed
import redis

# Optional PostgreSQL import
try:
    import psycopg2
    from psycopg2 import pool
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

# Import our services
from services.database_manager import DatabaseManager
from services.cache_manager import CacheManager
from services.background_tasks import BackgroundTaskManager
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

class HealthCheckService:
    """Comprehensive health checking service for all application components."""
    
    def __init__(self, db_manager: DatabaseManager, cache_manager: CacheManager, 
                 task_manager: BackgroundTaskManager, rate_limiter: RateLimiter):
        self.db_manager = db_manager
        self.cache_manager = cache_manager
        self.task_manager = task_manager
        self.rate_limiter = rate_limiter
        self.start_time = datetime.now()
        
    def get_basic_health(self) -> Dict[str, Any]:
        """Get basic application health status."""
        try:
            uptime = datetime.now() - self.start_time
            return {
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'uptime': str(uptime),
                'uptime_seconds': int(uptime.total_seconds()),
                'version': '1.0.0'
            }
        except Exception as e:
            logger.error(f"Basic health check failed: {e}")
            return {
                'status': 'unhealthy',
                'timestamp': datetime.now().isoformat(),
                'error': str(e)
            }
    
    def check_database_health(self) -> Dict[str, Any]:
        """Check database connectivity and performance."""
        start_time = time.time()
        try:
            # Test basic connectivity
            with self.db_manager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    cursor.fetchone()
            
            # Test connection pool status
            pool_info = self.db_manager.get_pool_status()
            
            # Measure response time
            response_time = (time.time() - start_time) * 1000
            
            status = 'healthy'
            if response_time > 1000:  # 1 second threshold
                status = 'degraded'
            elif response_time > 5000:  # 5 second threshold
                status = 'unhealthy'
            
            return {
                'status': status,
                'response_time_ms': round(response_time, 2),
                'pool_size': pool_info.get('pool_size', 0),
                'available_connections': pool_info.get('available', 0),
                'used_connections': pool_info.get('used', 0),
                'max_connections': pool_info.get('max_connections', 0)
            }
            
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                'status': 'unhealthy',
                'error': str(e),
                'response_time_ms': (time.time() - start_time) * 1000
            }
    
    def check_cache_health(self) -> Dict[str, Any]:
        """Check Redis cache connectivity and performance."""
        start_time = time.time()
        try:
            # Test basic connectivity
            test_key = f"health_check:{int(time.time())}"
            test_value = "ping"
            
            self.cache_manager.set(test_key, test_value, ttl=60)
            retrieved_value = self.cache_manager.get(test_key)
            self.cache_manager.delete(test_key)
            
            if retrieved_value != test_value:
                raise Exception("Cache read/write test failed")
            
            # Get cache statistics
            stats = self.cache_manager.get_stats()
            
            # Measure response time
            response_time = (time.time() - start_time) * 1000
            
            status = 'healthy'
            if response_time > 500:  # 500ms threshold
                status = 'degraded'
            elif response_time > 2000:  # 2 second threshold
                status = 'unhealthy'
            
            return {
                'status': status,
                'response_time_ms': round(response_time, 2),
                'hit_rate': stats.get('hit_rate', 0),
                'total_keys': stats.get('total_keys', 0),
                'memory_usage_mb': stats.get('memory_usage_mb', 0),
                'connected_clients': stats.get('connected_clients', 0)
            }
            
        except Exception as e:
            logger.error(f"Cache health check failed: {e}")
            return {
                'status': 'unhealthy',
                'error': str(e),
                'response_time_ms': (time.time() - start_time) * 1000
            }
    
    def check_task_system_health(self) -> Dict[str, Any]:
        """Check background task system health."""
        try:
            stats = self.task_manager.get_system_stats()
            
            # Determine health status based on queue sizes and worker availability
            status = 'healthy'
            pending_tasks = stats.get('pending_tasks', 0)
            active_workers = stats.get('active_workers', 0)
            max_workers = stats.get('max_workers', 1)
            
            if pending_tasks > 100:  # High queue threshold
                status = 'degraded'
            elif active_workers == 0 and pending_tasks > 0:
                status = 'unhealthy'
            elif active_workers < max_workers * 0.1:  # Less than 10% workers active
                status = 'degraded'
            
            return {
                'status': status,
                'pending_tasks': pending_tasks,
                'active_workers': active_workers,
                'max_workers': max_workers,
                'completed_tasks': stats.get('completed_tasks', 0),
                'failed_tasks': stats.get('failed_tasks', 0),
                'worker_utilization': round((active_workers / max_workers) * 100, 2) if max_workers > 0 else 0
            }
            
        except Exception as e:
            logger.error(f"Task system health check failed: {e}")
            return {
                'status': 'unhealthy',
                'error': str(e)
            }
    
    def check_system_resources(self) -> Dict[str, Any]:
        """Check system resource utilization."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            
            # Network statistics
            network = psutil.net_io_counters()
            
            # Determine overall system health
            status = 'healthy'
            if cpu_percent > 90 or memory_percent > 90 or disk_percent > 90:
                status = 'critical'
            elif cpu_percent > 80 or memory_percent > 80 or disk_percent > 80:
                status = 'degraded'
            
            return {
                'status': status,
                'cpu_percent': round(cpu_percent, 2),
                'memory_percent': round(memory_percent, 2),
                'memory_available_gb': round(memory.available / (1024**3), 2),
                'disk_percent': round(disk_percent, 2),
                'disk_free_gb': round(disk.free / (1024**3), 2),
                'network_bytes_sent': network.bytes_sent,
                'network_bytes_recv': network.bytes_recv,
                'load_average': list(psutil.getloadavg()) if hasattr(psutil, 'getloadavg') else None
            }
            
        except Exception as e:
            logger.error(f"System resource check failed: {e}")
            return {
                'status': 'unhealthy',
                'error': str(e)
            }
    
    def check_rate_limiter_health(self) -> Dict[str, Any]:
        """Check rate limiter functionality."""
        try:
            # Test rate limiter functionality
            test_key = f"health_check_rate_limit_{int(time.time())}"
            
            # Should allow first request
            allowed = self.rate_limiter.is_allowed(test_key, limit=5, window=60)
            if not allowed:
                raise Exception("Rate limiter unexpectedly blocked first request")
            
            # Get rate limiter statistics
            stats = self.rate_limiter.get_statistics()
            
            return {
                'status': 'healthy',
                'total_requests': stats.get('total_requests', 0),
                'blocked_requests': stats.get('blocked_requests', 0),
                'active_limits': stats.get('active_limits', 0),
                'block_rate': round(stats.get('block_rate', 0), 2)
            }
            
        except Exception as e:
            logger.error(f"Rate limiter health check failed: {e}")
            return {
                'status': 'unhealthy',
                'error': str(e)
            }
    
    def get_comprehensive_health(self) -> Dict[str, Any]:
        """Get comprehensive health status of all components."""
        start_time = time.time()
        
        # Run all health checks in parallel for faster response
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {
                'application': executor.submit(self.get_basic_health),
                'database': executor.submit(self.check_database_health),
                'cache': executor.submit(self.check_cache_health),
                'tasks': executor.submit(self.check_task_system_health),
                'system': executor.submit(self.check_system_resources),
                'rate_limiter': executor.submit(self.check_rate_limiter_health)
            }
            
            results = {}
            for component, future in futures.items():
                try:
                    results[component] = future.result(timeout=10)
                except Exception as e:
                    logger.error(f"Health check failed for {component}: {e}")
                    results[component] = {
                        'status': 'unhealthy',
                        'error': f"Health check timeout or error: {str(e)}"
                    }
        
        # Determine overall health status
        component_statuses = [result.get('status', 'unhealthy') for result in results.values()]
        
        if 'unhealthy' in component_statuses:
            overall_status = 'unhealthy'
        elif 'critical' in component_statuses:
            overall_status = 'critical'
        elif 'degraded' in component_statuses:
            overall_status = 'degraded'
        else:
            overall_status = 'healthy'
        
        total_time = (time.time() - start_time) * 1000
        
        return {
            'overall_status': overall_status,
            'timestamp': datetime.now().isoformat(),
            'response_time_ms': round(total_time, 2),
            'components': results
        }

# Create Flask Blueprint
health_bp = Blueprint('health', __name__)

# Global health service instance (will be initialized in app.py)
health_service: Optional[HealthCheckService] = None

def init_health_service(db_manager: DatabaseManager, cache_manager: CacheManager,
                       task_manager: BackgroundTaskManager, rate_limiter: RateLimiter):
    """Initialize the health service with required dependencies."""
    global health_service
    health_service = HealthCheckService(db_manager, cache_manager, task_manager, rate_limiter)

@health_bp.route('/health', methods=['GET'])
def basic_health():
    """Basic health check endpoint for load balancers."""
    if not health_service:
        return jsonify({'status': 'unhealthy', 'error': 'Health service not initialized'}), 503
    
    result = health_service.get_basic_health()
    status_code = 200 if result['status'] == 'healthy' else 503
    return jsonify(result), status_code

@health_bp.route('/health/detailed', methods=['GET'])
def detailed_health():
    """Detailed health check with all components."""
    if not health_service:
        return jsonify({'status': 'unhealthy', 'error': 'Health service not initialized'}), 503
    
    result = health_service.get_comprehensive_health()
    
    # Return appropriate HTTP status code
    status_codes = {
        'healthy': 200,
        'degraded': 200,  # Still operational
        'critical': 503,  # Service unavailable
        'unhealthy': 503  # Service unavailable
    }
    
    status_code = status_codes.get(result['overall_status'], 503)
    return jsonify(result), status_code

@health_bp.route('/health/database', methods=['GET'])
def database_health():
    """Database-specific health check."""
    if not health_service:
        return jsonify({'status': 'unhealthy', 'error': 'Health service not initialized'}), 503
    
    result = health_service.check_database_health()
    status_code = 200 if result['status'] == 'healthy' else 503
    return jsonify(result), status_code

@health_bp.route('/health/cache', methods=['GET'])
def cache_health():
    """Cache-specific health check."""
    if not health_service:
        return jsonify({'status': 'unhealthy', 'error': 'Health service not initialized'}), 503
    
    result = health_service.check_cache_health()
    status_code = 200 if result['status'] == 'healthy' else 503
    return jsonify(result), status_code

@health_bp.route('/health/tasks', methods=['GET'])
def task_health():
    """Task system health check."""
    if not health_service:
        return jsonify({'status': 'unhealthy', 'error': 'Health service not initialized'}), 503
    
    result = health_service.check_task_system_health()
    status_code = 200 if result['status'] == 'healthy' else 503
    return jsonify(result), status_code

@health_bp.route('/health/system', methods=['GET'])
def system_health():
    """System resources health check."""
    if not health_service:
        return jsonify({'status': 'unhealthy', 'error': 'Health service not initialized'}), 503
    
    result = health_service.check_system_resources()
    status_code = 200 if result['status'] in ['healthy', 'degraded'] else 503
    return jsonify(result), status_code

@health_bp.route('/readiness', methods=['GET'])
def readiness_check():
    """Kubernetes readiness probe endpoint."""
    if not health_service:
        return jsonify({'ready': False, 'error': 'Health service not initialized'}), 503
    
    # Check critical components for readiness
    db_health = health_service.check_database_health()
    cache_health = health_service.check_cache_health()
    
    ready = (db_health['status'] in ['healthy', 'degraded'] and 
             cache_health['status'] in ['healthy', 'degraded'])
    
    result = {
        'ready': ready,
        'timestamp': datetime.now().isoformat(),
        'database_status': db_health['status'],
        'cache_status': cache_health['status']
    }
    
    status_code = 200 if ready else 503
    return jsonify(result), status_code

@health_bp.route('/liveness', methods=['GET'])
def liveness_check():
    """Kubernetes liveness probe endpoint."""
    if not health_service:
        return jsonify({'alive': False, 'error': 'Health service not initialized'}), 503
    
    # Simple check that the application is running
    basic_health = health_service.get_basic_health()
    alive = basic_health['status'] == 'healthy'
    
    result = {
        'alive': alive,
        'timestamp': datetime.now().isoformat(),
        'uptime_seconds': basic_health.get('uptime_seconds', 0)
    }
    
    status_code = 200 if alive else 503
    return jsonify(result), status_code

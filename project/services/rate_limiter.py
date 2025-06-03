"""
Rate limiting and circuit breaker implementation for external API calls.
"""
import time
import threading
from typing import Dict, Any, Callable, Optional
from functools import wraps
from collections import defaultdict, deque
import logging

logger = logging.getLogger(__name__)

class RateLimiter:
    """Token bucket rate limiter"""
    
    def __init__(self, max_requests: int = 10, time_window: int = 60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = defaultdict(deque)
        self.lock = threading.Lock()
    
    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed for the given key"""
        with self.lock:
            now = time.time()
            # Remove requests outside the time window
            while self.requests[key] and self.requests[key][0] <= now - self.time_window:
                self.requests[key].popleft()
            
            # Check if we can make another request
            if len(self.requests[key]) < self.max_requests:
                self.requests[key].append(now)
                return True
            
            return False
    
    def wait_time(self, key: str) -> float:
        """Get time to wait before next request is allowed"""
        with self.lock:
            if not self.requests[key]:
                return 0
            
            oldest_request = self.requests[key][0]
            time_until_reset = oldest_request + self.time_window - time.time()
            return max(0, time_until_reset)


class CircuitBreaker:
    """Circuit breaker pattern implementation"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60, expected_exception: type = Exception):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
        self.lock = threading.Lock()
    
    def call(self, func: Callable, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        with self.lock:
            if self.state == 'OPEN':
                # Check if we should try to recover
                if time.time() - self.last_failure_time > self.recovery_timeout:
                    self.state = 'HALF_OPEN'
                    logger.info("Circuit breaker transitioning to HALF_OPEN")
                else:
                    raise Exception("Circuit breaker is OPEN")
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
            
        except self.expected_exception as e:
            self._on_failure()
            raise e
    
    def _on_success(self):
        """Handle successful call"""
        with self.lock:
            self.failure_count = 0
            if self.state == 'HALF_OPEN':
                self.state = 'CLOSED'
                logger.info("Circuit breaker closed after successful call")
    
    def _on_failure(self):
        """Handle failed call"""
        with self.lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = 'OPEN'
                logger.warning(f"Circuit breaker opened after {self.failure_count} failures")


class ServiceLimiter:
    """Combined rate limiting and circuit breaking for services"""
    
    def __init__(self):
        self.rate_limiters = {}
        self.circuit_breakers = {}
        self.lock = threading.Lock()
    
    def get_rate_limiter(self, service: str, max_requests: int = 10, time_window: int = 60) -> RateLimiter:
        """Get or create rate limiter for service"""
        with self.lock:
            if service not in self.rate_limiters:
                self.rate_limiters[service] = RateLimiter(max_requests, time_window)
            return self.rate_limiters[service]
    
    def get_circuit_breaker(self, service: str, failure_threshold: int = 5, recovery_timeout: int = 60) -> CircuitBreaker:
        """Get or create circuit breaker for service"""
        with self.lock:
            if service not in self.circuit_breakers:
                self.circuit_breakers[service] = CircuitBreaker(failure_threshold, recovery_timeout)
            return self.circuit_breakers[service]
    
    def call_with_protection(self, service: str, func: Callable, *args, **kwargs):
        """Call function with rate limiting and circuit breaker protection"""
        rate_limiter = self.get_rate_limiter(service)
        circuit_breaker = self.get_circuit_breaker(service)
        
        # Check rate limit
        if not rate_limiter.is_allowed(service):
            wait_time = rate_limiter.wait_time(service)
            raise Exception(f"Rate limit exceeded for {service}. Wait {wait_time:.2f} seconds")
        
        # Call with circuit breaker
        return circuit_breaker.call(func, *args, **kwargs)


# Global service limiter
service_limiter = ServiceLimiter()

def rate_limit(service: str, max_requests: int = 10, time_window: int = 60):
    """Decorator for rate limiting"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            rate_limiter = service_limiter.get_rate_limiter(service, max_requests, time_window)
            
            if not rate_limiter.is_allowed(service):
                wait_time = rate_limiter.wait_time(service)
                logger.warning(f"Rate limit exceeded for {service}. Waiting {wait_time:.2f} seconds")
                time.sleep(min(wait_time, 5))  # Cap wait time at 5 seconds
                
                # Try again after waiting
                if not rate_limiter.is_allowed(service):
                    raise Exception(f"Rate limit still exceeded for {service}")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

def circuit_breaker(service: str, failure_threshold: int = 5, recovery_timeout: int = 60):
    """Decorator for circuit breaker"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            circuit_breaker = service_limiter.get_circuit_breaker(service, failure_threshold, recovery_timeout)
            return circuit_breaker.call(func, *args, **kwargs)
        return wrapper
    return decorator

def with_protection(service: str, max_requests: int = 10, time_window: int = 60, 
                   failure_threshold: int = 5, recovery_timeout: int = 60):
    """Combined rate limiting and circuit breaker decorator"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            return service_limiter.call_with_protection(service, func, *args, **kwargs)
        return wrapper
    return decorator

def get_service_stats() -> Dict[str, Any]:
    """Get statistics for all protected services"""
    stats = {
        'rate_limiters': {},
        'circuit_breakers': {}
    }
    
    with service_limiter.lock:
        for service, limiter in service_limiter.rate_limiters.items():
            with limiter.lock:
                stats['rate_limiters'][service] = {
                    'max_requests': limiter.max_requests,
                    'time_window': limiter.time_window,
                    'current_requests': len(limiter.requests.get(service, []))
                }
        
        for service, breaker in service_limiter.circuit_breakers.items():
            with breaker.lock:
                stats['circuit_breakers'][service] = {
                    'state': breaker.state,
                    'failure_count': breaker.failure_count,
                    'failure_threshold': breaker.failure_threshold,
                    'last_failure_time': breaker.last_failure_time
                }
    
    return stats

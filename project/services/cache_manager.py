"""
Redis-based caching layer for scan results.
"""
try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

import json
import logging
import hashlib
from typing import Dict, Any, Optional, List
import time
from functools import wraps
import pickle

logger = logging.getLogger(__name__)

class CacheManager:
    """Cache manager supporting both Redis and in-memory caching"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = True
        self.redis_client = None
        self.memory_cache = {}
        self.cache_timestamps = {}
        self.use_redis = False

        # Determine cache type
        if config.get('type') == 'memory' or not HAS_REDIS:
            logger.info("Using in-memory cache")
            self.use_redis = False
        else:
            # Try to connect to Redis
            try:
                if HAS_REDIS:
                    redis_config = {
                        'host': config.get('host', 'localhost'),
                        'port': config.get('port', 6379),
                        'password': config.get('password', ''),
                        'db': config.get('db', 0),
                        'decode_responses': False  # Keep as bytes for pickle
                    }

                    self.redis_client = redis.Redis(**redis_config)
                    # Test connection
                    self.redis_client.ping()
                    self.use_redis = True
                    logger.info("Redis cache connected successfully")
                else:
                    raise Exception("Redis library not available")
            except Exception as e:
                logger.warning(f"Redis connection failed, using in-memory cache: {e}")
                self.use_redis = False

    def _generate_cache_key(self, domain: str, scan_type: str, **kwargs) -> str:
        """Generate a cache key for the scan"""
        # Ensure kwargs are sorted for consistent key generation
        sorted_kwargs = sorted(kwargs.items())
        key_data = f"{domain}:{scan_type}:{sorted_kwargs}"
        return f"scan_cache:{hashlib.md5(key_data.encode()).hexdigest()}"

    def get_cached_scan(self, domain: str, scan_type: str, max_age: int = 3600, **kwargs) -> Optional[Dict[str, Any]]:
        """Get cached scan result if available and not expired"""
        if not self.enabled:
            return None

        try:
            cache_key = self._generate_cache_key(domain, scan_type, **kwargs)

            if self.use_redis:
                cached_data = self.redis_client.get(cache_key)
                if cached_data:
                    result = pickle.loads(cached_data)

                    # Check if cache is expired
                    if time.time() - result.get('cached_at', 0) < max_age:
                        logger.info(f"Cache hit for {domain} ({scan_type})")
                        return result.get('data')
                    else:
                        logger.debug(f"Expired cache removed for {domain} ({scan_type}) from Redis")
                        # Remove expired cache
                        self.redis_client.delete(cache_key)
            else:
                # In-memory cache
                if cache_key in self.memory_cache:
                    result = self.memory_cache[cache_key]

                    # Check if cache is expired (using stored timestamp if available, else current time)
                    expiry_time = self.cache_timestamps.get(cache_key, float('inf'))
                    if time.time() < expiry_time:  # Check against explicit expiry time
                        logger.info(f"Cache hit for {domain} ({scan_type}) from memory")
                        return result.get('data')
                    else:
                        # Remove expired cache
                        logger.debug(f"Expired cache removed for {domain} ({scan_type}) from memory")
                        del self.memory_cache[cache_key]
                        if cache_key in self.cache_timestamps:
                            del self.cache_timestamps[cache_key]

            return None

        except Exception as e:
            logger.error(f"Cache get error: {e}")
            return None

    def cache_scan_result(self, domain: str, scan_type: str, data: Dict[str, Any], ttl: int = 3600, **kwargs):
        """Cache scan result with TTL"""
        if not self.enabled:
            return

        try:
            cache_key = self._generate_cache_key(domain, scan_type, **kwargs)
            cache_data = {
                'data': data,
                'cached_at': time.time(),
                'domain': domain,
                'scan_type': scan_type
            }

            if self.use_redis:
                serialized_data = pickle.dumps(cache_data)
                self.redis_client.setex(cache_key, ttl, serialized_data)
            else:
                # In-memory cache with manual TTL tracking
                self.memory_cache[cache_key] = cache_data
                self.cache_timestamps[cache_key] = time.time() + ttl

                # Clean up expired entries periodically
                self._cleanup_expired_memory_cache()

            logger.debug(f"Cached scan result for {domain} ({scan_type})")

        except Exception as e:
            logger.error(f"Cache set error: {e}")

    def _cleanup_expired_memory_cache(self):
        """Clean up expired entries from in-memory cache"""
        if self.use_redis:
            return

        current_time = time.time()
        expired_keys = []

        for key, expiry_time in list(self.cache_timestamps.items()):
            if current_time > expiry_time:
                expired_keys.append(key)

        for key in expired_keys:
            if key in self.memory_cache:
                del self.memory_cache[key]
            if key in self.cache_timestamps:
                del self.cache_timestamps[key]

        if expired_keys:
            logger.debug(f"Cleaned up {len(expired_keys)} expired memory cache entries")

    def invalidate_domain_cache(self, domain: str):
        """Invalidate all cached results for a domain"""
        if not self.enabled:
            return

        try:
            deleted_count = 0

            if self.use_redis:
                # Redis implementation
                pattern = "scan_cache:*"
                keys = self.redis_client.keys(pattern)

                for key in keys:
                    try:
                        cached_data = self.redis_client.get(key)
                        if cached_data:
                            result = pickle.loads(cached_data)
                            if result.get('domain') == domain:
                                self.redis_client.delete(key)
                                deleted_count += 1
                    except Exception as e:
                        logger.warning(f"Error processing Redis key {key} for invalidation: {e}")
                        continue
            else:
                # In-memory cache implementation
                keys_to_delete = []
                for key, cache_data in list(self.memory_cache.items()):
                    if cache_data.get('domain') == domain:
                        keys_to_delete.append(key)

                for key in keys_to_delete:
                    if key in self.memory_cache:
                        del self.memory_cache[key]
                    if key in self.cache_timestamps:
                        del self.cache_timestamps[key]
                    deleted_count += 1

            logger.info(f"Invalidated {deleted_count} cache entries for domain '{domain}'")

        except Exception as e:
            logger.error(f"Cache invalidation error for domain {domain}: {e}")

    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            if self.use_redis:
                # Redis statistics
                info = self.redis_client.info()
                return {
                    'cache_type': 'redis',
                    'total_keys': self.redis_client.dbsize(),
                    'memory_usage': info.get('used_memory', 0),
                    'hit_rate': info.get('keyspace_hits', 0) / max(info.get('keyspace_hits', 0) + info.get('keyspace_misses', 0), 1),
                    'connected_clients': info.get('connected_clients', 0)
                }
            else:
                # In-memory cache statistics
                current_time = time.time()
                valid_entries = sum(1 for exp_time in self.cache_timestamps.values() if exp_time > current_time)
                
                return {
                    'cache_type': 'memory',
                    'total_keys': len(self.memory_cache),
                    'valid_keys': valid_entries,
                    'expired_keys': len(self.memory_cache) - valid_entries,
                    'memory_usage_estimate': len(str(self.memory_cache))  # Rough estimate
                }

        except Exception as e:
            logger.error(f"Cache statistics error: {e}")
            return {'cache_type': 'unknown', 'error': str(e)}

    def clear_cache(self, pattern: str = "*"):
        """Clear cache entries matching pattern"""
        try:
            if self.use_redis:
                pattern = "scan_cache:*"
                keys = self.redis_client.keys(pattern)
                if keys:
                    deleted = self.redis_client.delete(*keys)
                    logger.info(f"Cleared {deleted} Redis cache entries matching '{pattern}'")
            else:
                # Clear in-memory cache
                cache_count = len(self.memory_cache)
                self.memory_cache.clear()
                self.cache_timestamps.clear()
                logger.info(f"Cleared {cache_count} memory cache entries")

        except Exception as e:
            logger.error(f"Cache clear error: {e}")

    # Generic cache methods used by other services
    def get(self, key: str) -> Optional[Any]:
        """Get value by key"""
        if not self.enabled:
            return None

        try:
            if self.use_redis:
                data = self.redis_client.get(key)
                return pickle.loads(data) if data else None
            else:
                # For in-memory, also check TTL before returning
                if key in self.memory_cache and time.time() < self.cache_timestamps.get(key, float('inf')):
                    return self.memory_cache.get(key)
                else:
                    # Clean up expired in-memory entry on access if found
                    if key in self.memory_cache:
                        del self.memory_cache[key]
                        if key in self.cache_timestamps:
                            del self.cache_timestamps[key]
                    return None
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            return None

    def set(self, key: str, value: Any, timeout: int = 3600, ttl: int = None):
        """Set value with timeout (ttl is alias for timeout for compatibility)"""
        if not self.enabled:
            return

        # Use ttl if provided, otherwise use timeout
        expiry_time = ttl if ttl is not None else timeout

        try:
            if self.use_redis:
                self.redis_client.setex(key, expiry_time, pickle.dumps(value))
            else:
                self.memory_cache[key] = value
                self.cache_timestamps[key] = time.time() + expiry_time
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")

    def delete(self, key: str):
        """Delete key"""
        if not self.enabled:
            return

        try:
            if self.use_redis:
                self.redis_client.delete(key)
            else:
                if key in self.memory_cache:
                    del self.memory_cache[key]
                if key in self.cache_timestamps:
                    del self.cache_timestamps[key]
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")

    def exists(self, key: str) -> bool:
        """Check if key exists"""
        if not self.enabled:
            return False

        try:
            if self.use_redis:
                return self.redis_client.exists(key)
            else:
                # Check both existence and TTL for in-memory
                if key in self.memory_cache:
                    expiry_time = self.cache_timestamps.get(key, float('inf'))
                    if time.time() < expiry_time:
                        return True
                    else:
                        # Clean up expired entry
                        del self.memory_cache[key]
                        if key in self.cache_timestamps:
                            del self.cache_timestamps[key]
                        return False
                return False
        except Exception as e:
            logger.error(f"Cache exists error for key {key}: {e}")
            return False

    def close(self):
        """Close cache connections"""
        try:
            if self.use_redis and self.redis_client:
                self.redis_client.close()
            else:
                self.memory_cache.clear()
                self.cache_timestamps.clear()
        except Exception as e:
            logger.error(f"Cache close error: {e}")


def cache_scan_result(ttl: int = 3600, cache_key_prefix: str = "scan"):
    """Decorator to cache scan results"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key from function name and arguments
            cache_key = f"{cache_key_prefix}:{func.__name__}:{hash(str(args) + str(sorted(kwargs.items())))}"
            
            # Try to get cached result
            cache_manager = get_cache_manager()
            if cache_manager:
                cached_result = cache_manager.get(cache_key)
                if cached_result is not None:
                    logger.debug(f"Cache hit for {func.__name__}")
                    return cached_result

            # Execute function and cache result
            try:
                result = func(*args, **kwargs)
                if cache_manager and result is not None:
                    cache_manager.set(cache_key, result, timeout=ttl)
                    logger.debug(f"Cached result for {func.__name__}")
                return result
            except Exception as e:
                logger.error(f"Error in cached function {func.__name__}: {e}")
                raise e

        return wrapper
    return decorator


# Global cache manager instance
_cache_manager = None

def get_cache_manager() -> Optional[CacheManager]:
    """Get the global cache manager instance"""
    global _cache_manager
    return _cache_manager

def init_cache_manager(config: Dict[str, Any]) -> CacheManager:
    """Initialize the global cache manager"""
    global _cache_manager
    _cache_manager = CacheManager(config)
    logger.info("Cache manager initialized")
    return _cache_manager
                        del self.cache_timestamps[key]
                    deleted_count += 1

            logger.info(f"Invalidated {deleted_count} cache entries for {domain}")

        except Exception as e:
            logger.error(f"Cache invalidation error: {e}")

    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get cache statistics"""
        if not self.enabled:
            return {'enabled': False}

        try:
            if self.use_redis:
                info = self.redis_client.info()
                pattern = "scan_cache:*"
                cache_keys = self.redis_client.keys(pattern) # This can be slow for large datasets

                return {
                    'enabled': True,
                    'type': 'redis',
                    'total_keys': len(cache_keys),
                    'memory_usage': info.get('used_memory_human', 'Unknown'),
                    'connected_clients': info.get('connected_clients', 0),
                    'hits': info.get('keyspace_hits', 0),
                    'misses': info.get('keyspace_misses', 0)
                }
            else:
                # In-memory cache statistics
                return {
                    'enabled': True,
                    'type': 'memory',
                    'total_keys': len(self.memory_cache),
                    'memory_usage': f"{len(self.memory_cache)} entries",
                    'connected_clients': 1,
                    'hits': 0,  # Would need to track separately
                    'misses': 0  # Would need to track separately
                }

        except Exception as e:
            logger.error(f"Cache statistics error: {e}")
            return {'enabled': True, 'error': str(e)}

    def clear_all_cache(self):
        """Clear all scan cache entries"""
        if not self.enabled:
            return

        try:
            if self.use_redis:
                pattern = "scan_cache:*"
                keys = self.redis_client.keys(pattern)
                if keys:
                    deleted = self.redis_client.delete(*keys)
                    logger.info(f"Cleared {deleted} Redis cache entries matching '{pattern}'")
            else:
                # Clear in-memory cache
                cache_count = len(self.memory_cache)
                self.memory_cache.clear()
                self.cache_timestamps.clear()
                logger.info(f"Cleared {cache_count} memory cache entries")

        except Exception as e:
            logger.error(f"Cache clear error: {e}")

    # Generic cache methods used by other services
    def get(self, key: str) -> Optional[Any]:
        """Get value by key"""
        if not self.enabled:
            return None

        try:
            if self.use_redis:
                data = self.redis_client.get(key)
                return pickle.loads(data) if data else None
            else:
                # For in-memory, also check TTL before returning
                if key in self.memory_cache and time.time() < self.cache_timestamps.get(key, float('inf')):
                    return self.memory_cache.get(key)
                else:
                    # Clean up expired in-memory entry on access if found
                    if key in self.memory_cache:
                        del self.memory_cache[key]
                        if key in self.cache_timestamps:
                            del self.cache_timestamps[key]
                    return None
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
                        return None
            
    def set(self, key: str, value: Any, timeout: int = 3600, ttl: int = None):
        """Set value with timeout (ttl is alias for timeout for compatibility)"""
        if not self.enabled:
            return

        # Use ttl if provided, otherwise use timeout
        expiry_time = ttl if ttl is not None else timeout

        try:
            if self.use_redis:
                self.redis_client.setex(key, expiry_time, pickle.dumps(value))
            else:
                self.memory_cache[key] = value
                self.cache_timestamps[key] = time.time() + expiry_time
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")

    def delete(self, key: str):
        """Delete key"""
        if not self.enabled:
            return

        try:
            if self.use_redis:
                self.redis_client.delete(key)
            else:
                if key in self.memory_cache:
                    del self.memory_cache[key]
                if key in self.cache_timestamps:
                    del self.cache_timestamps[key]
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")

    def exists(self, key: str) -> bool:
        """Check if key exists"""
        if not self.enabled:
            return False

        try:
            if self.use_redis:
                return self.redis_client.exists(key)
            else:
                # For in-memory, also check TTL
                return key in self.memory_cache and time.time() < self.cache_timestamps.get(key, float('inf'))
        except Exception as e:
            logger.error(f"Cache exists check error for key {key}: {e}")
            return False


def cache_scan_result(cache_key_params: Dict[str, Any] = None, ttl: int = 3600):
    """Decorator to cache scan results"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache_manager = get_cache_manager()

            # Extract domain from args/kwargs
            domain = None
            if args:
                # Assume domain is the first positional argument
                domain = args[0]
            elif 'domain' in kwargs:
                domain = kwargs['domain']

            if not domain or not cache_manager.enabled:
                return func(*args, **kwargs)

            # Generate cache parameters
            scan_type = func.__name__ # Use function name as scan_type
            # Combine decorator-defined params with function call kwargs
            combined_cache_params = {}
            if cache_key_params:
                combined_cache_params.update(cache_key_params)
            combined_cache_params.update(kwargs) # kwargs from the decorated function call

            # Try to get cached result
            cached_result = cache_manager.get_cached_scan(
                domain, scan_type, max_age=ttl, **combined_cache_params
            )

            if cached_result is not None:
                return cached_result

            # Execute function and cache result
            result = func(*args, **kwargs)

            if result is not None: # Only cache if result is not None
                cache_manager.cache_scan_result(
                    domain, scan_type, result, ttl=ttl, **combined_cache_params
                )

            return result

        return wrapper
    return decorator


class CacheWarmer:
    """Background cache warming for popular domains"""

    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager

    def warm_popular_domains(self, domains: List[str]):
        """Pre-cache results for popular domains"""
        if not self.cache_manager.enabled:
            return

        logger.info(f"Starting cache warming for {len(domains)} domains")

        # This would typically run in a background task
        # For now, just log the intent, or trigger actual scans if possible.
        # Example:
        # for domain in domains:
        #     logger.debug(f"Attempting to warm cache for {domain}")
        #     # Call a dummy scan function or actual scan entry point
        #     # e.g., dummy_scan_function(domain=domain, scan_type="popular")
        #     # which would be decorated with @cache_scan_result
        for domain in domains:
            logger.debug(f"Would warm cache for {domain}")


# Global cache manager instance
cache_manager = None

def get_cache_manager() -> CacheManager:
    """Get or create the global cache manager. Initializes with default in-memory config if not set."""
    global cache_manager
    if cache_manager is None:
        # Default configuration: try Redis, fallback to memory
        default_config = {
            'type': 'redis' if HAS_REDIS else 'memory',
            'host': 'localhost',
            'port': 6379,
            'db': 0
        }
        cache_manager = CacheManager(default_config)
    return cache_manager

def configure_cache(config: Dict[str, Any]):
    """
    Configure the global cache manager.
    Expected config structure:
    {
        'type': 'redis' or 'memory',
        'host': 'localhost',
        'port': 6379,
        'password': 'your_redis_password',
        'db': 0,
        'enabled': True # Optional, defaults to True
    }
    """
    global cache_manager
    # Set default for 'enabled' if not provided in config
    config.setdefault('enabled', True)
    cache_manager = CacheManager(config)
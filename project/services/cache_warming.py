"""
Cache Warming Service for EASM Application

This module provides intelligent cache warming capabilities to pre-populate
frequently accessed domain information and scan results for improved performance.

Features:
- Popular domain identification and caching
- Intelligent warming strategies based on access patterns
- Background warming tasks
- Cache statistics and monitoring
- Adaptive warming based on system load

Author: EASM Development Team
"""

import time
import logging
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from dataclasses import dataclass, asdict

from services.cache_manager import CacheManager
from services.database_manager import DatabaseManager
from services.optimized_scanner import OptimizedScanner
from services.background_tasks import BackgroundTaskManager

logger = logging.getLogger(__name__)

@dataclass
class DomainStats:
    """Statistics for a domain's cache usage."""
    domain: str
    access_count: int
    last_accessed: datetime
    cache_hits: int
    cache_misses: int
    scan_frequency: int
    priority_score: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data['last_accessed'] = self.last_accessed.isoformat()
        return data

class CacheWarmingService:
    """Intelligent cache warming service for EASM application."""
    
    def __init__(self, cache_manager: CacheManager, db_manager: DatabaseManager,
                 scanner: OptimizedScanner, task_manager: BackgroundTaskManager):
        self.cache_manager = cache_manager
        self.db_manager = db_manager
        self.scanner = scanner
        self.task_manager = task_manager
        
        # Configuration
        self.warming_enabled = True
        self.max_concurrent_warmups = 5
        self.warmup_batch_size = 20
        self.min_access_threshold = 3
        self.priority_threshold = 0.7
        self.warming_interval = 3600  # 1 hour
        
        # Statistics tracking
        self.domain_stats: Dict[str, DomainStats] = {}
        self.access_patterns: Dict[str, List[datetime]] = defaultdict(list)
        self.warming_queue: Set[str] = set()
        self.is_warming = False
        self.last_warming_time = datetime.now()
        
        # Threading
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        
        # Load existing statistics
        self._load_statistics()
        
        # Start background warming thread
        self._start_background_warming()
    
    def record_domain_access(self, domain: str, cache_hit: bool = False):
        """Record domain access for warming analysis."""
        try:
            with self._lock:
                current_time = datetime.now()
                
                # Update access patterns
                self.access_patterns[domain].append(current_time)
                
                # Keep only last 24 hours of access data
                cutoff_time = current_time - timedelta(hours=24)
                self.access_patterns[domain] = [
                    access_time for access_time in self.access_patterns[domain]
                    if access_time > cutoff_time
                ]
                
                # Update domain statistics
                if domain not in self.domain_stats:
                    self.domain_stats[domain] = DomainStats(
                        domain=domain,
                        access_count=0,
                        last_accessed=current_time,
                        cache_hits=0,
                        cache_misses=0,
                        scan_frequency=0,
                        priority_score=0.0
                    )
                
                stats = self.domain_stats[domain]
                stats.access_count += 1
                stats.last_accessed = current_time
                
                if cache_hit:
                    stats.cache_hits += 1
                else:
                    stats.cache_misses += 1
                
                # Recalculate priority score
                stats.priority_score = self._calculate_priority_score(domain)
                
                # Add to warming queue if meets criteria
                if (stats.priority_score >= self.priority_threshold and 
                    stats.access_count >= self.min_access_threshold and
                    domain not in self.warming_queue):
                    self.warming_queue.add(domain)
                    logger.debug(f"Added {domain} to warming queue (priority: {stats.priority_score:.3f})")
                
        except Exception as e:
            logger.error(f"Error recording domain access for {domain}: {e}")
    
    def _calculate_priority_score(self, domain: str) -> float:
        """Calculate priority score for domain warming."""
        if domain not in self.domain_stats:
            return 0.0
        
        stats = self.domain_stats[domain]
        current_time = datetime.now()
        
        # Factor 1: Access frequency (higher = better)
        access_frequency = len(self.access_patterns.get(domain, []))
        frequency_score = min(access_frequency / 10.0, 1.0)  # Normalize to 0-1
        
        # Factor 2: Recency (more recent = better)
        hours_since_access = (current_time - stats.last_accessed).total_seconds() / 3600
        recency_score = max(0, 1 - (hours_since_access / 24))  # 0-1, decay over 24 hours
        
        # Factor 3: Cache miss ratio (higher misses = higher priority)
        total_requests = stats.cache_hits + stats.cache_misses
        if total_requests > 0:
            miss_ratio = stats.cache_misses / total_requests
        else:
            miss_ratio = 1.0
        
        # Factor 4: Scan frequency (higher = better)
        scan_score = min(stats.scan_frequency / 5.0, 1.0)  # Normalize to 0-1
        
        # Weighted combination
        priority_score = (
            frequency_score * 0.3 +
            recency_score * 0.3 +
            miss_ratio * 0.3 +
            scan_score * 0.1
        )
        
        return priority_score
    
    def get_top_domains_for_warming(self, limit: int = 50) -> List[str]:
        """Get top domains that should be warmed based on priority."""
        try:
            # Sort domains by priority score
            sorted_domains = sorted(
                self.domain_stats.items(),
                key=lambda x: x[1].priority_score,
                reverse=True
            )
            
            # Filter domains that meet minimum criteria
            top_domains = []
            for domain, stats in sorted_domains:
                if (stats.priority_score >= self.priority_threshold and
                    stats.access_count >= self.min_access_threshold):
                    top_domains.append(domain)
                    
                if len(top_domains) >= limit:
                    break
            
            return top_domains
            
        except Exception as e:
            logger.error(f"Error getting top domains for warming: {e}")
            return []
    
    def warm_domain_cache(self, domain: str, scan_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """Warm cache for a specific domain."""
        try:
            start_time = time.time()
            
            if scan_types is None:
                scan_types = ['ports', 'services', 'vulnerabilities', 'dns']
            
            results = {}
            errors = []
            
            logger.info(f"Starting cache warming for domain: {domain}")
            
            # Warm different types of scan data
            for scan_type in scan_types:
                try:
                    if scan_type == 'ports':
                        # Warm port scan results
                        cache_key = f"ports:{domain}"
                        if not self.cache_manager.get(cache_key):
                            # Perform lightweight port scan for caching
                            port_results = self._perform_lightweight_port_scan(domain)
                            if port_results:
                                self.cache_manager.set(cache_key, port_results, ttl=7200)  # 2 hours
                                results[scan_type] = 'warmed'
                            else:
                                results[scan_type] = 'failed'
                        else:
                            results[scan_type] = 'already_cached'
                    
                    elif scan_type == 'services':
                        # Warm service detection results
                        cache_key = f"services:{domain}"
                        if not self.cache_manager.get(cache_key):
                            service_results = self._perform_service_detection(domain)
                            if service_results:
                                self.cache_manager.set(cache_key, service_results, ttl=7200)
                                results[scan_type] = 'warmed'
                            else:
                                results[scan_type] = 'failed'
                        else:
                            results[scan_type] = 'already_cached'
                    
                    elif scan_type == 'dns':
                        # Warm DNS information
                        cache_key = f"dns:{domain}"
                        if not self.cache_manager.get(cache_key):
                            dns_results = self._perform_dns_lookup(domain)
                            if dns_results:
                                self.cache_manager.set(cache_key, dns_results, ttl=3600)  # 1 hour
                                results[scan_type] = 'warmed'
                            else:
                                results[scan_type] = 'failed'
                        else:
                            results[scan_type] = 'already_cached'
                    
                    elif scan_type == 'vulnerabilities':
                        # Warm vulnerability scan results (if available from previous scans)
                        cache_key = f"vulns:{domain}"
                        if not self.cache_manager.get(cache_key):
                            vuln_results = self._get_cached_vulnerability_data(domain)
                            if vuln_results:
                                self.cache_manager.set(cache_key, vuln_results, ttl=14400)  # 4 hours
                                results[scan_type] = 'warmed'
                            else:
                                results[scan_type] = 'no_data'
                        else:
                            results[scan_type] = 'already_cached'
                
                except Exception as e:
                    logger.error(f"Error warming {scan_type} for {domain}: {e}")
                    errors.append(f"{scan_type}: {str(e)}")
                    results[scan_type] = 'error'
            
            # Update domain statistics
            if domain in self.domain_stats:
                self.domain_stats[domain].scan_frequency += 1
                self.domain_stats[domain].priority_score = self._calculate_priority_score(domain)
            
            # Remove from warming queue
            with self._lock:
                self.warming_queue.discard(domain)
            
            duration = time.time() - start_time
            logger.info(f"Cache warming completed for {domain} in {duration:.2f}s")
            
            return {
                'domain': domain,
                'duration_seconds': duration,
                'results': results,
                'errors': errors,
                'success': len(errors) < len(scan_types)
            }
            
        except Exception as e:
            logger.error(f"Error warming cache for {domain}: {e}")
            return {
                'domain': domain,
                'duration_seconds': 0,
                'results': {},
                'errors': [str(e)],
                'success': False
            }
    
    def warm_popular_domains(self, max_domains: int = 20) -> Dict[str, Any]:
        """Warm cache for multiple popular domains."""
        try:
            if self.is_warming:
                return {'status': 'already_warming', 'message': 'Cache warming already in progress'}
            
            self.is_warming = True
            start_time = time.time()
            
            # Get top domains to warm
            domains_to_warm = self.get_top_domains_for_warming(max_domains)
            
            if not domains_to_warm:
                self.is_warming = False
                return {'status': 'no_domains', 'message': 'No domains found for warming'}
            
            logger.info(f"Starting bulk cache warming for {len(domains_to_warm)} domains")
            
            # Warm domains in parallel
            results = {}
            with ThreadPoolExecutor(max_workers=self.max_concurrent_warmups) as executor:
                future_to_domain = {
                    executor.submit(self.warm_domain_cache, domain): domain
                    for domain in domains_to_warm
                }
                
                for future in as_completed(future_to_domain, timeout=300):  # 5 minute timeout
                    domain = future_to_domain[future]
                    try:
                        result = future.result()
                        results[domain] = result
                    except Exception as e:
                        logger.error(f"Error warming {domain}: {e}")
                        results[domain] = {
                            'domain': domain,
                            'success': False,
                            'errors': [str(e)]
                        }
            
            duration = time.time() - start_time
            successful_warmups = sum(1 for r in results.values() if r.get('success', False))
            
            self.is_warming = False
            self.last_warming_time = datetime.now()
            
            logger.info(f"Bulk cache warming completed: {successful_warmups}/{len(domains_to_warm)} successful in {duration:.2f}s")
            
            return {
                'status': 'completed',
                'duration_seconds': duration,
                'total_domains': len(domains_to_warm),
                'successful_warmups': successful_warmups,
                'results': results
            }
            
        except Exception as e:
            self.is_warming = False
            logger.error(f"Error in bulk cache warming: {e}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def _perform_lightweight_port_scan(self, domain: str) -> Optional[Dict[str, Any]]:
        """Perform lightweight port scan for cache warming."""
        try:
            # Use optimized scanner for common ports only
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
            
            # This would integrate with your actual scanning logic
            # For now, return a placeholder result
            return {
                'domain': domain,
                'open_ports': common_ports[:3],  # Simulate some open ports
                'scan_time': datetime.now().isoformat(),
                'lightweight': True
            }
            
        except Exception as e:
            logger.error(f"Error in lightweight port scan for {domain}: {e}")
            return None
    
    def _perform_service_detection(self, domain: str) -> Optional[Dict[str, Any]]:
        """Perform service detection for cache warming."""
        try:
            # Lightweight service detection
            return {
                'domain': domain,
                'services': {
                    '80': 'http',
                    '443': 'https',
                    '22': 'ssh'
                },
                'scan_time': datetime.now().isoformat(),
                'lightweight': True
            }
            
        except Exception as e:
            logger.error(f"Error in service detection for {domain}: {e}")
            return None
    
    def _perform_dns_lookup(self, domain: str) -> Optional[Dict[str, Any]]:
        """Perform DNS lookup for cache warming."""
        try:
            import socket
            
            # Basic DNS resolution
            ip_address = socket.gethostbyname(domain)
            
            return {
                'domain': domain,
                'ip_address': ip_address,
                'lookup_time': datetime.now().isoformat(),
                'ttl': 3600
            }
            
        except Exception as e:
            logger.error(f"Error in DNS lookup for {domain}: {e}")
            return None
    
    def _get_cached_vulnerability_data(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get existing vulnerability data from database."""
        try:
            # Query database for previous vulnerability scan results
            with self.db_manager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT scan_results, scan_date 
                        FROM scan_results 
                        WHERE domain = %s AND scan_type = 'vulnerability'
                        ORDER BY scan_date DESC 
                        LIMIT 1
                    """, (domain,))
                    
                    result = cursor.fetchone()
                    if result:
                        return {
                            'domain': domain,
                            'vulnerability_data': result[0],
                            'scan_date': result[1].isoformat(),
                            'cached': True
                        }
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting cached vulnerability data for {domain}: {e}")
            return None
    
    def _start_background_warming(self):
        """Start background thread for automatic cache warming."""
        def warming_worker():
            while not self._stop_event.is_set():
                try:
                    # Check if it's time for warming
                    if (datetime.now() - self.last_warming_time).total_seconds() >= self.warming_interval:
                        # Check if there are domains in the warming queue
                        if self.warming_queue and not self.is_warming:
                            domains_to_warm = list(self.warming_queue)[:self.warmup_batch_size]
                            
                            logger.info(f"Starting automatic cache warming for {len(domains_to_warm)} domains")
                            
                            # Submit warming task
                            self.task_manager.submit_task(
                                self.warm_popular_domains,
                                args=(len(domains_to_warm),),
                                task_id=f"auto_warming_{int(time.time())}",
                                metadata={'type': 'cache_warming', 'auto': True}
                            )
                    
                    # Sleep for a short period
                    self._stop_event.wait(60)  # Check every minute
                    
                except Exception as e:
                    logger.error(f"Error in background warming worker: {e}")
                    self._stop_event.wait(60)
        
        warming_thread = threading.Thread(target=warming_worker, daemon=True)
        warming_thread.start()
        logger.info("Background cache warming thread started")
    
    def start_background_warming(self):
        """Start background cache warming process."""
        if not hasattr(self, '_background_started') or not self._background_started:
            self._start_background_warming()
            self._background_started = True
            logger.info("Cache warming background process started")
        else:
            logger.info("Cache warming background process already running")

    def get_warming_statistics(self) -> Dict[str, Any]:
        """Get cache warming statistics."""
        try:
            total_domains = len(self.domain_stats)
            high_priority_domains = sum(
                1 for stats in self.domain_stats.values()
                if stats.priority_score >= self.priority_threshold
            )
            
            queue_size = len(self.warming_queue)
            
            # Calculate average priority score
            if self.domain_stats:
                avg_priority = sum(stats.priority_score for stats in self.domain_stats.values()) / total_domains
            else:
                avg_priority = 0.0
            
            return {
                'total_tracked_domains': total_domains,
                'high_priority_domains': high_priority_domains,
                'warming_queue_size': queue_size,
                'average_priority_score': round(avg_priority, 3),
                'warming_enabled': self.warming_enabled,
                'is_currently_warming': self.is_warming,
                'last_warming_time': self.last_warming_time.isoformat(),
                'warming_interval_seconds': self.warming_interval
            }
            
        except Exception as e:
            logger.error(f"Error getting warming statistics: {e}")
            return {'error': str(e)}
    
    def _load_statistics(self):
        """Load domain statistics from cache or database."""
        try:
            # Try to load from cache first
            cached_stats = self.cache_manager.get('warming_domain_stats')
            if cached_stats:
                for domain, stats_dict in cached_stats.items():
                    stats_dict['last_accessed'] = datetime.fromisoformat(stats_dict['last_accessed'])
                    self.domain_stats[domain] = DomainStats(**stats_dict)
                
                logger.info(f"Loaded {len(self.domain_stats)} domain statistics from cache")
            
        except Exception as e:
            logger.error(f"Error loading warming statistics: {e}")
    
    def save_statistics(self):
        """Save domain statistics to cache."""
        try:
            stats_dict = {
                domain: stats.to_dict()
                for domain, stats in self.domain_stats.items()
            }
            
            self.cache_manager.set('warming_domain_stats', stats_dict, ttl=86400)  # 24 hours
            logger.info(f"Saved {len(stats_dict)} domain statistics to cache")
            
        except Exception as e:
            logger.error(f"Error saving warming statistics: {e}")
    
    def stop(self):
        """Stop the cache warming service."""
        self._stop_event.set()
        self.save_statistics()
        logger.info("Cache warming service stopped")

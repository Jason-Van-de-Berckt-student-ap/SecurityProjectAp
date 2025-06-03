"""
Optimized scanning service for parallel processing.
"""
import concurrent.futures
import time
import logging
from typing import Dict, List, Optional, Any
from functools import wraps
import threading

# Import existing services
from services.dns_service import get_dns_records
from services.ssl_service import get_ssl_info
from services.vuln_service import check_vulnerabilities_alternative
from services.subdomain_service import find_subdomains
from services.domain_service import find_related_domains
from services.Darkweb import check_ahmia

# Import optimization services
from services.database_manager import get_db_manager
from services.cache_manager import get_cache_manager, cache_scan_result

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ScanMetrics:
    """Track scan performance metrics"""
    def __init__(self):
        self.scans = {}
        self.lock = threading.Lock()
    
    def start_scan(self, scan_id: str, domain: str):
        with self.lock:
            self.scans[scan_id] = {
                'domain': domain,
                'start_time': time.time(),
                'services': {},
                'status': 'running'
            }
    
    def log_service(self, scan_id: str, service: str, duration: float, success: bool):
        with self.lock:
            if scan_id in self.scans:
                self.scans[scan_id]['services'][service] = {
                    'duration': duration,
                    'success': success
                }
    
    def end_scan(self, scan_id: str):
        with self.lock:
            if scan_id in self.scans:
                self.scans[scan_id]['end_time'] = time.time()
                self.scans[scan_id]['status'] = 'completed'
                total_duration = self.scans[scan_id]['end_time'] - self.scans[scan_id]['start_time']
                logger.info(f"Scan {scan_id} completed in {total_duration:.2f}s")

# Global metrics instance
metrics = ScanMetrics()

def log_scan_duration(service_name: str):
    """Decorator to log scan durations"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            domain = args[0] if args else "unknown"
            start_time = time.time()
            scan_id = f"{domain}_{int(start_time)}"
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                metrics.log_service(scan_id, service_name, duration, True)
                logger.info(f"{service_name} for {domain} completed in {duration:.2f}s")
                return result
            except Exception as e:
                duration = time.time() - start_time
                metrics.log_service(scan_id, service_name, duration, False)
                logger.error(f"{service_name} for {domain} failed after {duration:.2f}s: {str(e)}")
                raise
        return wrapper
    return decorator

# Wrap existing services with logging and caching
@cache_scan_result(ttl=1800)  # Cache for 30 minutes
@log_scan_duration("DNS")
def dns_scan_with_logging(domain):
    return get_dns_records(domain)

@cache_scan_result(ttl=3600)  # Cache for 1 hour
@log_scan_duration("SSL")  
def ssl_scan_with_logging(domain):
    return get_ssl_info(domain)

@cache_scan_result(ttl=1800)  # Cache for 30 minutes
@log_scan_duration("Vulnerability")
def vuln_scan_with_logging(domain):
    return check_vulnerabilities_alternative(domain)

@cache_scan_result(ttl=7200)  # Cache for 2 hours (subdomains change less frequently)
@log_scan_duration("Subdomain")
def subdomain_scan_with_logging(domain):
    return find_subdomains(domain)

@cache_scan_result(ttl=7200)  # Cache for 2 hours
@log_scan_duration("Related Domains")
def related_domains_with_logging(domain, api_key):
    return find_related_domains(domain, api_key)

@cache_scan_result(ttl=3600)  # Cache for 1 hour
@log_scan_duration("Darkweb")
def darkweb_scan_with_logging(domain):
    return check_ahmia(domain)

class OptimizedScanner:
    """Optimized scanner with parallel processing capabilities"""
    
    def __init__(self, max_workers: int = 6, timeout: int = 300):
        self.max_workers = max_workers
        self.timeout = timeout
        
    def scan_domain_parallel(self, domain: str, scan_options: Dict[str, bool], brave_api_key: str = None) -> Dict[str, Any]:
        """
        Scan a domain with parallel service execution.
        
        Args:
            domain: Domain to scan
            scan_options: Dictionary of scan types to enable
            brave_api_key: API key for related domains service
            
        Returns:
            Dictionary containing scan results
        """
        scan_id = f"{domain}_{int(time.time())}"
        metrics.start_scan(scan_id, domain)
        
        logger.info(f"Starting parallel scan for {domain}")
        
        # Initialize results
        results = {
            'dns_info': {},
            'ssl_info': {},
            'vulnerabilities': [],
            'subdomains': [],
            'related_domains': [],
            'onion_links': {'interested_links': [], 'other_links': []}
        }
        
        # Prepare scan tasks
        tasks = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit scan tasks based on options
            if scan_options.get('dns_scan', False):
                tasks['dns'] = executor.submit(dns_scan_with_logging, domain)
                
            if scan_options.get('ssl_scan', False):
                tasks['ssl'] = executor.submit(ssl_scan_with_logging, domain)
                
            if scan_options.get('vuln_scan', False):
                tasks['vuln'] = executor.submit(vuln_scan_with_logging, domain)
                
            if scan_options.get('subdomain_scan', False):
                tasks['subdomain'] = executor.submit(subdomain_scan_with_logging, domain)
                
            if scan_options.get('related_domains', False):
                tasks['related'] = executor.submit(related_domains_with_logging, domain, brave_api_key)
                
            if scan_options.get('darkweb', False):
                tasks['darkweb'] = executor.submit(darkweb_scan_with_logging, domain)
            
            # Collect results as they complete
            for task_name, future in tasks.items():
                try:
                    result = future.result(timeout=self.timeout)
                    
                    # Map results to correct keys
                    if task_name == 'dns':
                        results['dns_info'] = result
                    elif task_name == 'ssl':
                        results['ssl_info'] = result
                    elif task_name == 'vuln':
                        results['vulnerabilities'] = result
                    elif task_name == 'subdomain':
                        results['subdomains'] = result
                    elif task_name == 'related':
                        results['related_domains'] = result
                    elif task_name == 'darkweb':
                        results['onion_links'] = result
                        
                    logger.info(f"Completed {task_name} scan for {domain}")
                    
                except concurrent.futures.TimeoutError:
                    logger.error(f"Timeout in {task_name} scan for {domain}")
                    # Set default error values
                    if task_name == 'dns':
                        results['dns_info'] = {"error": "Timeout"}
                    elif task_name == 'ssl':
                        results['ssl_info'] = {"error": "Timeout"}
                    elif task_name == 'vuln':
                        results['vulnerabilities'] = []
                    elif task_name == 'subdomain':
                        results['subdomains'] = []
                    elif task_name == 'related':
                        results['related_domains'] = []
                    elif task_name == 'darkweb':
                        results['onion_links'] = {'interested_links': [], 'other_links': []}
                        
                except Exception as e:
                    logger.error(f"Error in {task_name} scan for {domain}: {str(e)}")
                    # Set default error values
                    if task_name == 'dns':
                        results['dns_info'] = {"error": str(e)}
                    elif task_name == 'ssl':
                        results['ssl_info'] = {"error": str(e)}
                    elif task_name == 'vuln':
                        results['vulnerabilities'] = []
                    elif task_name == 'subdomain':
                        results['subdomains'] = []
                    elif task_name == 'related':
                        results['related_domains'] = []
                    elif task_name == 'darkweb':
                        results['onion_links'] = {'interested_links': [], 'other_links': []}
            metrics.end_scan(scan_id)
        
        # Store scan result in database
        try:
            db_manager = get_db_manager()
            scan_result = {
                'domain': domain,
                'scan_type': 'single',
                'dns_records': str(results.get('dns_info', {})),
                'ssl_info': str(results.get('ssl_info', {})),
                'vulnerabilities': str(results.get('vulnerabilities', [])),
                'subdomains': str(results.get('subdomains', [])),
                'related_domains': str(results.get('related_domains', [])),
                'darkweb_mentions': str(results.get('onion_links', {})),
                'timestamp': time.time()
            }
            db_manager.batch_insert_scan_results([scan_result])
        except Exception as e:
            logger.error(f"Failed to store scan result for {domain}: {e}")
        
        logger.info(f"Completed parallel scan for {domain}")
        return results

    def scan_domains_batch_parallel(self, domains: List[str], scan_options: Dict[str, bool], 
                                   brave_api_key: str = None, max_concurrent_domains: int = 3) -> Dict[str, Any]:
        """
        Scan multiple domains in parallel.
        
        Args:
            domains: List of domains to scan
            scan_options: Dictionary of scan types to enable
            brave_api_key: API key for related domains service
            max_concurrent_domains: Maximum number of domains to process concurrently
            
        Returns:
            Dictionary containing results for all domains
        """
        logger.info(f"Starting batch scan for {len(domains)} domains")
        all_results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent_domains) as executor:
            # Submit domain scan tasks
            domain_futures = {
                executor.submit(self.scan_domain_parallel, domain, scan_options, brave_api_key): domain
                for domain in domains
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(domain_futures):
                domain = domain_futures[future]
                try:
                    result = future.result()
                    all_results[domain] = {
                        'status': 'completed',
                        'results': result
                    }
                    logger.info(f"Completed scan for domain: {domain}")
                    
                except Exception as e:
                    logger.error(f"Failed scan for domain {domain}: {str(e)}")
                    all_results[domain] = {
                        'status': 'error',
                        'error': str(e)
                    }
            logger.info(f"Completed batch scan for {len(domains)} domains")
        
        # Store all successful scan results in database as batch
        try:
            db_manager = get_db_manager()
            scan_results = []
            
            for domain, domain_result in all_results.items():
                if domain_result['status'] == 'completed':
                    results = domain_result['results']
                    scan_result = {
                        'domain': domain,
                        'scan_type': 'batch',
                        'dns_records': str(results.get('dns_info', {})),
                        'ssl_info': str(results.get('ssl_info', {})),
                        'vulnerabilities': str(results.get('vulnerabilities', [])),
                        'subdomains': str(results.get('subdomains', [])),
                        'related_domains': str(results.get('related_domains', [])),
                        'darkweb_mentions': str(results.get('onion_links', {})),
                        'timestamp': time.time()
                    }
                    scan_results.append(scan_result)
            
            if scan_results:
                db_manager.batch_insert_scan_results(scan_results)
                logger.info(f"Stored {len(scan_results)} scan results in database")
                
        except Exception as e:
            logger.error(f"Failed to store batch scan results: {e}")
        
        return all_results

# Global scanner instance
optimized_scanner = OptimizedScanner()

def validate_domain(domain: str) -> bool:
    """
    Validate domain input.
    
    Args:
        domain: Domain string to validate
        
    Returns:
        bool: True if domain is valid, False otherwise
    """
    if not domain or not isinstance(domain, str):
        return False
    
    # Remove protocol if present
    domain = domain.replace('http://', '').replace('https://', '')
    
    # Basic domain validation using regex
    import re
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    return bool(domain_pattern.match(domain)) and len(domain) <= 253

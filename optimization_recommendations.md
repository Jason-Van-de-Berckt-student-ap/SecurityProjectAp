# EASM Scanner Optimization Analysis

## Performance Optimization Areas

### 1. Parallelization & Concurrency

#### Current Issues:

- Batch scans process domains sequentially (one-by-one)
- Each domain waits for the previous to complete entirely
- No parallel execution of different scan types
- ThreadPoolExecutor used only within subdomain service (max_workers=20)

#### Recommended Solutions:

**A. Domain-Level Parallelization:**

```python
# Implement parallel domain processing in batch scans
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as domain_executor:
    domain_futures = []
    for domain in domains:
        future = domain_executor.submit(process_single_domain, domain, scan_options)
        domain_futures.append(future)

    # Process results as they complete
    for future in concurrent.futures.as_completed(domain_futures):
        try:
            result = future.result()
            # Handle result
        except Exception as e:
            # Handle error
```

**B. Service-Level Parallelization:**

```python
# Within each domain scan, parallelize different scan types
def process_domain_parallel(domain, scan_options):
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = {}

        if scan_options['dns_scan']:
            futures['dns'] = executor.submit(get_dns_records, domain)
        if scan_options['ssl_scan']:
            futures['ssl'] = executor.submit(get_ssl_info, domain)
        if scan_options['vuln_scan']:
            futures['vuln'] = executor.submit(check_vulnerabilities_alternative, domain)
        if scan_options['subdomain_scan']:
            futures['subdomain'] = executor.submit(find_subdomains, domain)
        if scan_options['related_domains']:
            futures['related'] = executor.submit(find_related_domains, domain, BRAVE_API_KEY)
        if scan_options['darkweb']:
            futures['darkweb'] = executor.submit(check_ahmia, domain)

        # Collect results
        results = {}
        for scan_type, future in futures.items():
            try:
                results[scan_type] = future.result(timeout=300)  # 5 min timeout per service
            except Exception as e:
                results[scan_type] = {"error": str(e)}

        return results
```

### 2. Database Optimization

#### Current Issues:

- Individual database connections for each operation
- No connection pooling
- Synchronous database writes in batch processing
- Cleanup operations run after each domain

#### Recommended Solutions:

**A. Connection Pooling:**

```python
import sqlite3
from threading import Lock

class DatabasePool:
    def __init__(self, db_path='easm.db', max_connections=10):
        self.db_path = db_path
        self.max_connections = max_connections
        self.connections = []
        self.lock = Lock()

    def get_connection(self):
        with self.lock:
            if self.connections:
                return self.connections.pop()
            return sqlite3.connect(self.db_path)

    def return_connection(self, conn):
        with self.lock:
            if len(self.connections) < self.max_connections:
                self.connections.append(conn)
            else:
                conn.close()
```

**B. Batch Database Operations:**

```python
def batch_insert_scans(scan_results):
    """Insert multiple scan results in a single transaction"""
    conn = sqlite3.connect('easm.db')
    try:
        c = conn.cursor()

        # Prepare batch insert data
        insert_data = []
        for domain, results in scan_results.items():
            insert_data.append((
                domain,
                datetime.now(),
                json.dumps(results.get('dns_info', {})),
                json.dumps(results.get('ssl_info', {})),
                json.dumps(results.get('vulnerabilities', [])),
                json.dumps(results.get('subdomains', [])),
                json.dumps(results.get('related_domains', [])),
                json.dumps(results.get('onion_links', {})),
                batch_id,
                1
            ))

        # Batch insert
        c.executemany('''INSERT INTO scans
                         (domain, scan_date, dns_records, ssl_info, vulnerabilities,
                          subdomains, related_domains, onion_links, batch_id, is_batch_scan)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', insert_data)
        conn.commit()
    finally:
        conn.close()
```

### 3. Memory Management

#### Current Issues:

- All results stored in memory before database write
- Large CSV files created in memory for downloads
- No streaming for large datasets

#### Recommended Solutions:

**A. Streaming CSV Generation:**

```python
from flask import Response
import io

def stream_csv_results(domains_results):
    """Stream CSV results instead of loading all in memory"""
    def generate():
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Domain', 'Category', 'Finding', 'Details'])
        yield output.getvalue()
        output.truncate(0)
        output.seek(0)

        for domain, results in domains_results:
            # Write domain results row by row
            for category, findings in results.items():
                for finding in findings:
                    writer.writerow([domain, category, finding.get('title', ''), finding.get('description', '')])
                    yield output.getvalue()
                    output.truncate(0)
                    output.seek(0)

    return Response(generate(), mimetype='text/csv')
```

### 4. Caching Implementation

#### Current Issues:

- No caching of scan results
- Repeated API calls for same domains
- No rate limiting consideration

#### Recommended Solutions:

**A. Redis Caching:**

```python
import redis
import pickle
from datetime import timedelta

class ScanCache:
    def __init__(self, redis_url='redis://localhost:6379'):
        self.redis_client = redis.from_url(redis_url)
        self.cache_ttl = timedelta(hours=24)  # Cache for 24 hours

    def get_cached_result(self, domain, scan_type):
        """Get cached scan result for domain and scan type"""
        cache_key = f"scan:{domain}:{scan_type}"
        cached_data = self.redis_client.get(cache_key)
        if cached_data:
            return pickle.loads(cached_data)
        return None

    def cache_result(self, domain, scan_type, result):
        """Cache scan result"""
        cache_key = f"scan:{domain}:{scan_type}"
        self.redis_client.setex(
            cache_key,
            self.cache_ttl,
            pickle.dumps(result)
        )
```

### 5. API Rate Limiting & Throttling

#### Current Issues:

- No rate limiting for external API calls
- Potential for API quota exhaustion
- No backoff strategies

#### Recommended Solutions:

**A. Rate Limiting with Backoff:**

```python
import time
from functools import wraps

def rate_limit(calls_per_second=1):
    """Decorator to rate limit function calls"""
    min_interval = 1.0 / calls_per_second
    last_called = [0.0]

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            left_to_wait = min_interval - elapsed
            if left_to_wait > 0:
                time.sleep(left_to_wait)
            ret = func(*args, **kwargs)
            last_called[0] = time.time()
            return ret
        return wrapper
    return decorator

@rate_limit(calls_per_second=0.5)  # Max 1 call every 2 seconds
def query_external_api(domain):
    # API call implementation
    pass
```

### 6. Error Handling & Resilience

#### Current Issues:

- Single point of failure stops entire batch
- Limited error recovery
- No partial result handling

#### Recommended Solutions:

**A. Resilient Batch Processing:**

```python
def resilient_batch_process(domains, scan_options):
    """Process batch with error isolation and partial results"""
    successful_results = {}
    failed_domains = {}

    for domain in domains:
        try:
            # Try processing domain
            result = process_domain_with_retries(domain, scan_options, max_retries=3)
            successful_results[domain] = result

        except Exception as e:
            failed_domains[domain] = str(e)
            # Continue with next domain
            continue

    return successful_results, failed_domains

def process_domain_with_retries(domain, scan_options, max_retries=3):
    """Process domain with retry logic"""
    for attempt in range(max_retries):
        try:
            return process_single_domain(domain, scan_options)
        except Exception as e:
            if attempt == max_retries - 1:
                raise e
            time.sleep(2 ** attempt)  # Exponential backoff
```

### 7. Resource Management

#### Current Issues:

- Unbounded thread creation in subdomain service
- No resource cleanup
- Memory leaks in long-running processes

#### Recommended Solutions:

**A. Resource Pool Management:**

```python
class ResourceManager:
    def __init__(self):
        self.max_concurrent_domains = 5
        self.max_threads_per_service = 10
        self.active_scans = 0
        self.semaphore = threading.Semaphore(self.max_concurrent_domains)

    def acquire_scan_slot(self):
        return self.semaphore.acquire()

    def release_scan_slot(self):
        return self.semaphore.release()

    @contextmanager
    def scan_context(self):
        self.acquire_scan_slot()
        try:
            yield
        finally:
            self.release_scan_slot()
```

### 8. Monitoring & Metrics

#### Current Issues:

- No performance monitoring
- No scan duration tracking
- Limited progress visibility

#### Recommended Solutions:

**A. Performance Monitoring:**

```python
import time
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class ScanMetrics:
    domain: str
    start_time: float
    end_time: float = None
    scan_types: Dict[str, float] = None
    errors: List[str] = None

    def duration(self):
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time

class MetricsCollector:
    def __init__(self):
        self.metrics = []

    def start_scan(self, domain):
        metric = ScanMetrics(domain=domain, start_time=time.time())
        self.metrics.append(metric)
        return metric

    def end_scan(self, metric):
        metric.end_time = time.time()
```

## Implementation Priority

1. **High Priority:**

   - Service-level parallelization (immediate 3-5x speed improvement)
   - Database connection pooling
   - Basic error isolation

2. **Medium Priority:**

   - Domain-level parallelization for batch scans
   - Caching implementation
   - Rate limiting

3. **Low Priority:**
   - Streaming responses
   - Advanced monitoring
   - Resource pool management

## Expected Performance Improvements

- **Batch Processing:** 5-10x faster with parallel domain processing
- **Individual Scans:** 3-5x faster with service parallelization
- **Database Performance:** 2-3x improvement with connection pooling
- **Memory Usage:** 50-70% reduction with streaming
- **API Reliability:** 90%+ success rate with retry logic

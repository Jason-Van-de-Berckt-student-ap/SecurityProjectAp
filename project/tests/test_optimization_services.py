import unittest
import tempfile
import os
import sqlite3
import threading
import time
from unittest.mock import Mock, patch, MagicMock
import sys

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.database_manager import DatabaseManager
from services.cache_manager import CacheManager
from services.rate_limiter import RateLimiter
from services.background_tasks import BackgroundTaskManager
from services.optimized_scanner import OptimizedScanner


class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        """Set up test database manager with temporary database."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.db_manager = DatabaseManager(self.temp_db.name, max_connections=3)
    
    def tearDown(self):
        """Clean up test database."""
        self.db_manager.close_all()
        os.unlink(self.temp_db.name)
    
    def test_connection_pool_initialization(self):
        """Test that connection pool is properly initialized."""
        self.assertEqual(len(self.db_manager.connection_pool), 3)
        self.assertFalse(self.db_manager.shutdown_event.is_set())
    
    def test_get_connection(self):
        """Test getting a connection from the pool."""
        conn = self.db_manager.get_connection()
        self.assertIsNotNone(conn)
        self.assertIsInstance(conn, sqlite3.Connection)
        self.db_manager.return_connection(conn)
    
    def test_connection_pool_exhaustion(self):
        """Test behavior when connection pool is exhausted."""
        connections = []
        # Get all available connections
        for i in range(3):
            conn = self.db_manager.get_connection()
            connections.append(conn)
        
        # This should timeout since pool is exhausted
        start_time = time.time()
        conn = self.db_manager.get_connection(timeout=1)
        self.assertIsNone(conn)
        self.assertGreaterEqual(time.time() - start_time, 1)
        
        # Return connections
        for conn in connections:
            self.db_manager.return_connection(conn)
    
    def test_execute_query(self):
        """Test executing a query."""
        # Create test table
        self.db_manager.execute_query(
            "CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)"
        )
        
        # Insert data
        result = self.db_manager.execute_query(
            "INSERT INTO test (name) VALUES (?)", ("test_name",)
        )
        self.assertTrue(result)
        
        # Query data
        results = self.db_manager.execute_query(
            "SELECT * FROM test WHERE name = ?", ("test_name",), fetch=True
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][1], "test_name")
    
    def test_batch_insert(self):
        """Test batch insert functionality."""
        # Create test table
        self.db_manager.execute_query(
            "CREATE TABLE test_batch (id INTEGER PRIMARY KEY, value TEXT)"
        )
        
        # Prepare batch data
        data = [("value1",), ("value2",), ("value3",)]
        
        # Execute batch insert
        result = self.db_manager.batch_insert(
            "INSERT INTO test_batch (value) VALUES (?)", data, batch_size=2
        )
        self.assertTrue(result)
        
        # Verify data
        results = self.db_manager.execute_query(
            "SELECT COUNT(*) FROM test_batch", fetch=True
        )
        self.assertEqual(results[0][0], 3)
    
    def test_concurrent_access(self):
        """Test concurrent database access."""
        # Create test table
        self.db_manager.execute_query(
            "CREATE TABLE concurrent_test (id INTEGER PRIMARY KEY, thread_id INTEGER)"
        )
        
        results = []
        
        def worker(thread_id):
            for i in range(5):
                result = self.db_manager.execute_query(
                    "INSERT INTO concurrent_test (thread_id) VALUES (?)", 
                    (thread_id,)
                )
                results.append(result)
        
        # Start multiple threads
        threads = []
        for i in range(3):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        # Wait for completion
        for t in threads:
            t.join()
        
        # Verify all inserts succeeded
        self.assertTrue(all(results))
        
        # Verify total count
        count_result = self.db_manager.execute_query(
            "SELECT COUNT(*) FROM concurrent_test", fetch=True
        )
        self.assertEqual(count_result[0][0], 15)


class TestCacheManager(unittest.TestCase):
    def setUp(self):
        """Set up test cache manager with mock Redis."""
        with patch('redis.Redis') as mock_redis:
            mock_redis_instance = MagicMock()
            mock_redis.return_value = mock_redis_instance
            self.cache_manager = CacheManager()
            self.mock_redis = mock_redis_instance
    
    def test_cache_initialization(self):
        """Test cache manager initialization."""
        self.assertIsNotNone(self.cache_manager.redis_client)
        self.assertEqual(self.cache_manager.cache_stats['hits'], 0)
        self.assertEqual(self.cache_manager.cache_stats['misses'], 0)
    
    def test_cache_set_get(self):
        """Test setting and getting cache values."""
        # Mock Redis responses
        self.mock_redis.get.return_value = None
        self.mock_redis.setex.return_value = True
        
        # Test cache miss
        result = self.cache_manager.get('test_key')
        self.assertIsNone(result)
        self.assertEqual(self.cache_manager.cache_stats['misses'], 1)
        
        # Test cache set
        self.cache_manager.set('test_key', {'data': 'test'}, ttl=300)
        self.mock_redis.setex.assert_called_once()
        
        # Mock cache hit
        self.mock_redis.get.return_value = '{"data": "test"}'
        result = self.cache_manager.get('test_key')
        self.assertEqual(result, {'data': 'test'})
        self.assertEqual(self.cache_manager.cache_stats['hits'], 1)
    
    def test_cache_invalidation(self):
        """Test cache invalidation."""
        self.cache_manager.invalidate('test_key')
        self.mock_redis.delete.assert_called_once_with('test_key')
        
        self.cache_manager.invalidate_pattern('domain:*')
        self.mock_redis.eval.assert_called_once()
    
    def test_cached_decorator(self):
        """Test the cached decorator functionality."""
        call_count = 0
        
        @self.cache_manager.cached(ttl=300)
        def test_function(param):
            nonlocal call_count
            call_count += 1
            return f"result_{param}"
        
        # Mock cache miss then hit
        self.mock_redis.get.side_effect = [None, '{"result": "result_test"}']
        self.mock_redis.setex.return_value = True
        
        # First call should execute function
        result1 = test_function("test")
        self.assertEqual(call_count, 1)
        
        # Second call should use cache (mocked)
        result2 = test_function("test")
        self.assertEqual(call_count, 1)  # Function not called again
    
    def test_cache_stats(self):
        """Test cache statistics tracking."""
        stats = self.cache_manager.get_stats()
        self.assertIn('hits', stats)
        self.assertIn('misses', stats)
        self.assertIn('hit_rate', stats)
        
        # Simulate some hits and misses
        self.cache_manager.cache_stats['hits'] = 7
        self.cache_manager.cache_stats['misses'] = 3
        
        stats = self.cache_manager.get_stats()
        self.assertEqual(stats['hit_rate'], 0.7)


class TestRateLimiter(unittest.TestCase):
    def setUp(self):
        """Set up test rate limiter."""
        self.rate_limiter = RateLimiter(requests_per_minute=60, burst_size=10)
    
    def test_rate_limiter_initialization(self):
        """Test rate limiter initialization."""
        self.assertEqual(self.rate_limiter.requests_per_minute, 60)
        self.assertEqual(self.rate_limiter.burst_size, 10)
        self.assertEqual(self.rate_limiter.tokens, 10)
    
    def test_token_acquisition(self):
        """Test token acquisition."""
        # Should have full bucket initially
        self.assertTrue(self.rate_limiter.acquire())
        self.assertEqual(self.rate_limiter.tokens, 9)
        
        # Exhaust all tokens
        for _ in range(9):
            self.assertTrue(self.rate_limiter.acquire())
        
        # Should be empty now
        self.assertFalse(self.rate_limiter.acquire())
        self.assertEqual(self.rate_limiter.tokens, 0)
    
    def test_token_refill(self):
        """Test token bucket refill."""
        # Exhaust tokens
        for _ in range(10):
            self.rate_limiter.acquire()
        
        # Fast-forward time to trigger refill
        self.rate_limiter.last_refill = time.time() - 61  # 1 minute ago
        
        # Should refill tokens
        self.assertTrue(self.rate_limiter.acquire())
        self.assertGreater(self.rate_limiter.tokens, 0)
    
    def test_circuit_breaker(self):
        """Test circuit breaker functionality."""
        # Initially closed
        self.assertEqual(self.rate_limiter.circuit_state, 'closed')
        
        # Trigger failures to open circuit
        for _ in range(6):  # failure_threshold is 5
            self.rate_limiter.record_failure()
        
        self.assertEqual(self.rate_limiter.circuit_state, 'open')
        self.assertFalse(self.rate_limiter.acquire())
        
        # Test half-open state after timeout
        self.rate_limiter.circuit_opened_at = time.time() - 61  # 1 minute ago
        self.rate_limiter.circuit_state = 'open'
        
        # Should transition to half-open
        self.assertTrue(self.rate_limiter.acquire())
        self.assertEqual(self.rate_limiter.circuit_state, 'half-open')
    
    def test_circuit_recovery(self):
        """Test circuit breaker recovery."""
        # Open the circuit
        for _ in range(6):
            self.rate_limiter.record_failure()
        
        # Transition to half-open
        self.rate_limiter.circuit_opened_at = time.time() - 61
        self.rate_limiter.circuit_state = 'open'
        self.rate_limiter.acquire()  # Transitions to half-open
        
        # Record successes to close circuit
        for _ in range(3):  # success_threshold is 3
            self.rate_limiter.record_success()
        
        self.assertEqual(self.rate_limiter.circuit_state, 'closed')


class TestBackgroundTaskManager(unittest.TestCase):
    def setUp(self):
        """Set up test background task manager."""
        self.task_manager = BackgroundTaskManager(max_workers=2)
    
    def tearDown(self):
        """Clean up task manager."""
        self.task_manager.shutdown()
    
    def test_task_submission(self):
        """Test task submission."""
        def dummy_task():
            time.sleep(0.1)
            return "completed"
        
        task_id = self.task_manager.submit_task(dummy_task, task_type="test")
        self.assertIsNotNone(task_id)
        self.assertIn(task_id, self.task_manager.tasks)
        
        # Wait for completion
        time.sleep(0.2)
        task_info = self.task_manager.get_task_status(task_id)
        self.assertEqual(task_info['status'], 'completed')
    
    def test_task_with_args(self):
        """Test task submission with arguments."""
        def task_with_args(x, y, z=None):
            return x + y + (z or 0)
        
        task_id = self.task_manager.submit_task(
            task_with_args, args=(1, 2), kwargs={'z': 3}, task_type="math"
        )
        
        # Wait for completion
        time.sleep(0.1)
        task_info = self.task_manager.get_task_status(task_id)
        self.assertEqual(task_info['status'], 'completed')
        self.assertEqual(task_info.get('result'), 6)
    
    def test_task_failure(self):
        """Test task failure handling."""
        def failing_task():
            raise ValueError("Test error")
        
        task_id = self.task_manager.submit_task(failing_task, task_type="failing")
        
        # Wait for completion
        time.sleep(0.1)
        task_info = self.task_manager.get_task_status(task_id)
        self.assertEqual(task_info['status'], 'failed')
        self.assertIn('error', task_info)
    
    def test_task_cancellation(self):
        """Test task cancellation."""
        def long_running_task():
            time.sleep(1)
            return "completed"
        
        task_id = self.task_manager.submit_task(long_running_task, task_type="long")
        
        # Cancel task
        success = self.task_manager.cancel_task(task_id)
        self.assertTrue(success)
        
        time.sleep(0.1)
        task_info = self.task_manager.get_task_status(task_id)
        self.assertEqual(task_info['status'], 'cancelled')
    
    def test_task_queue_limit(self):
        """Test task queue size limit."""
        def dummy_task():
            time.sleep(0.1)
        
        # Fill up the queue (max_workers=2, so 2 running + queue)
        task_ids = []
        for i in range(5):
            task_id = self.task_manager.submit_task(dummy_task, task_type="queue_test")
            if task_id:
                task_ids.append(task_id)
        
        # Should have some tasks queued
        self.assertGreater(len(task_ids), 0)
        
        # Wait for completion
        time.sleep(0.5)
        
        # Check that tasks completed
        for task_id in task_ids:
            task_info = self.task_manager.get_task_status(task_id)
            self.assertIn(task_info['status'], ['completed', 'running'])
    
    def test_get_all_tasks(self):
        """Test getting all tasks."""
        def dummy_task():
            return "done"
        
        # Submit multiple tasks
        task_ids = []
        for i in range(3):
            task_id = self.task_manager.submit_task(dummy_task, task_type=f"test_{i}")
            task_ids.append(task_id)
        
        all_tasks = self.task_manager.get_all_tasks()
        self.assertGreaterEqual(len(all_tasks), 3)
        
        # Check that our tasks are in the list
        all_task_ids = [task['id'] for task in all_tasks]
        for task_id in task_ids:
            self.assertIn(task_id, all_task_ids)


class TestOptimizedScanner(unittest.TestCase):
    def setUp(self):
        """Set up test optimized scanner with mocked services."""
        with patch.multiple(
            'services.optimized_scanner',
            DatabaseManager=MagicMock(),
            CacheManager=MagicMock(),
            RateLimiter=MagicMock(),
            BackgroundTaskManager=MagicMock()
        ):
            self.scanner = OptimizedScanner()
            
            # Mock the service methods
            self.mock_dns_service = MagicMock()
            self.mock_subdomain_service = MagicMock()
            self.mock_domain_service = MagicMock()
            self.mock_vuln_service = MagicMock()
            
            # Patch the actual service imports
            with patch.dict('sys.modules', {
                'services.dns_service': self.mock_dns_service,
                'services.subdomain_service': self.mock_subdomain_service,
                'services.domain_service': self.mock_domain_service,
                'services.vuln_service': self.mock_vuln_service
            }):
                self.scanner._import_services()
    
    def test_scanner_initialization(self):
        """Test scanner initialization."""
        self.assertIsNotNone(self.scanner.db_manager)
        self.assertIsNotNone(self.scanner.cache_manager)
        self.assertIsNotNone(self.scanner.rate_limiter)
        self.assertEqual(self.scanner.max_workers, 6)
    
    @patch('services.optimized_scanner.validate_domain')
    def test_scan_domain_invalid(self, mock_validate):
        """Test scanning an invalid domain."""
        mock_validate.return_value = False
        
        result = self.scanner.scan_domain("invalid-domain")
        
        self.assertFalse(result['success'])
        self.assertIn('error', result)
    
    @patch('services.optimized_scanner.validate_domain')
    def test_scan_domain_rate_limited(self, mock_validate):
        """Test scanning when rate limited."""
        mock_validate.return_value = True
        self.scanner.rate_limiter.acquire.return_value = False
        
        result = self.scanner.scan_domain("example.com")
        
        self.assertFalse(result['success'])
        self.assertIn('rate limited', result['error'].lower())
    
    @patch('services.optimized_scanner.validate_domain')
    def test_scan_domain_success(self, mock_validate):
        """Test successful domain scan."""
        mock_validate.return_value = True
        self.scanner.rate_limiter.acquire.return_value = True
        
        # Mock service responses
        self.mock_dns_service.get_dns_info.return_value = {'dns': 'info'}
        self.mock_subdomain_service.get_subdomains.return_value = ['sub1.example.com']
        self.mock_domain_service.get_domain_info.return_value = {'domain': 'info'}
        self.mock_vuln_service.check_vulnerabilities.return_value = {'vulns': []}
        
        result = self.scanner.scan_domain("example.com")
        
        self.assertTrue(result['success'])
        self.assertIn('results', result)
        self.assertIn('performance', result)
    
    def test_batch_scan(self):
        """Test batch scanning functionality."""
        domains = ["example1.com", "example2.com", "example3.com"]
        
        with patch.object(self.scanner, 'scan_domain') as mock_scan:
            mock_scan.return_value = {'success': True, 'results': {}}
            
            results = self.scanner.batch_scan(domains, max_concurrent=2)
            
            self.assertEqual(len(results), 3)
            self.assertEqual(mock_scan.call_count, 3)
    
    def test_background_scan(self):
        """Test background scanning."""
        with patch.object(self.scanner, 'scan_domain') as mock_scan:
            mock_scan.return_value = {'success': True}
            
            task_id = self.scanner.scan_domain_background("example.com")
            
            self.assertIsNotNone(task_id)
            self.scanner.task_manager.submit_task.assert_called_once()


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestDatabaseManager))
    test_suite.addTest(unittest.makeSuite(TestCacheManager))
    test_suite.addTest(unittest.makeSuite(TestRateLimiter))
    test_suite.addTest(unittest.makeSuite(TestBackgroundTaskManager))
    test_suite.addTest(unittest.makeSuite(TestOptimizedScanner))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with error code if tests failed
    sys.exit(0 if result.wasSuccessful() else 1)

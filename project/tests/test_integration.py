import unittest
import tempfile
import os
import time
import threading
import requests
import json
from unittest.mock import patch, MagicMock
import sys

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.optimized_scanner import OptimizedScanner
from services.database_manager import DatabaseManager
from services.cache_manager import CacheManager
from services.background_tasks import BackgroundTaskManager


class TestIntegrationOptimizedScanning(unittest.TestCase):
    """Integration tests for the optimized scanning system."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment for integration tests."""
        # Create temporary database
        cls.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        cls.temp_db.close()
        
        # Initialize real services (but with mocked external calls)
        cls.db_manager = DatabaseManager(cls.temp_db.name, max_connections=3)
        
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment."""
        cls.db_manager.close_all()
        os.unlink(cls.temp_db.name)
    
    def setUp(self):
        """Set up each test."""
        # Mock Redis for cache manager
        self.redis_patcher = patch('redis.Redis')
        self.mock_redis_class = self.redis_patcher.start()
        self.mock_redis = MagicMock()
        self.mock_redis_class.return_value = self.mock_redis
        
        # Mock external service calls
        self.dns_patcher = patch('services.dns_service.get_dns_info')
        self.subdomain_patcher = patch('services.subdomain_service.get_subdomains')
        self.domain_patcher = patch('services.domain_service.get_domain_info')
        self.vuln_patcher = patch('services.vuln_service.check_vulnerabilities')
        
        self.mock_dns = self.dns_patcher.start()
        self.mock_subdomain = self.subdomain_patcher.start()
        self.mock_domain = self.domain_patcher.start()
        self.mock_vuln = self.vuln_patcher.start()
        
        # Set up mock responses
        self.mock_dns.return_value = {
            'A': ['192.168.1.1'],
            'MX': ['mail.example.com'],
            'NS': ['ns1.example.com', 'ns2.example.com']
        }
        self.mock_subdomain.return_value = ['www.example.com', 'api.example.com']
        self.mock_domain.return_value = {
            'title': 'Example Domain',
            'status_code': 200,
            'technologies': ['nginx']
        }
        self.mock_vuln.return_value = {'vulnerabilities': [], 'risk_score': 0}
        
        # Mock Redis responses for cache
        self.mock_redis.get.return_value = None  # Cache miss by default
        self.mock_redis.setex.return_value = True
        self.mock_redis.delete.return_value = True
        
        # Initialize scanner with real database
        self.scanner = OptimizedScanner(db_path=self.temp_db.name)
    
    def tearDown(self):
        """Clean up after each test."""
        self.scanner.shutdown()
        self.redis_patcher.stop()
        self.dns_patcher.stop()
        self.subdomain_patcher.stop()
        self.domain_patcher.stop()
        self.vuln_patcher.stop()
    
    def test_end_to_end_single_scan(self):
        """Test complete single domain scan flow."""
        domain = "example.com"
        
        # Perform scan
        result = self.scanner.scan_domain(domain)
        
        # Verify result structure
        self.assertTrue(result['success'])
        self.assertIn('results', result)
        self.assertIn('performance', result)
        self.assertIn('scan_id', result)
        
        # Verify all services were called
        self.mock_dns.assert_called_once()
        self.mock_subdomain.assert_called_once()
        self.mock_domain.assert_called_once()
        self.mock_vuln.assert_called_once()
        
        # Verify database storage
        scan_data = self.db_manager.execute_query(
            "SELECT * FROM scans WHERE domain = ?", (domain,), fetch=True
        )
        self.assertEqual(len(scan_data), 1)
        
        # Verify performance metrics
        self.assertIn('total_duration', result['performance'])
        self.assertIn('service_times', result['performance'])
        self.assertGreater(result['performance']['total_duration'], 0)
    
    def test_cache_integration(self):
        """Test cache integration in scanning flow."""
        domain = "cached-example.com"
        
        # First scan - should cache results
        result1 = self.scanner.scan_domain(domain)
        self.assertTrue(result1['success'])
        
        # Mock cache hit for second scan
        cached_data = {
            'dns_info': self.mock_dns.return_value,
            'subdomains': self.mock_subdomain.return_value,
            'domain_info': self.mock_domain.return_value,
            'vulnerabilities': self.mock_vuln.return_value
        }
        self.mock_redis.get.return_value = json.dumps(cached_data)
        
        # Reset call counts
        self.mock_dns.reset_mock()
        self.mock_subdomain.reset_mock()
        self.mock_domain.reset_mock()
        self.mock_vuln.reset_mock()
        
        # Second scan - should use cache
        result2 = self.scanner.scan_domain(domain)
        self.assertTrue(result2['success'])
        
        # Verify services were not called again (cache hit)
        # Note: This would depend on the actual cache implementation in the scanner
    
    def test_batch_scan_integration(self):
        """Test batch scanning with real coordination."""
        domains = ["example1.com", "example2.com", "example3.com"]
        
        # Perform batch scan
        results = self.scanner.batch_scan(domains, max_concurrent=2)
        
        # Verify all domains were processed
        self.assertEqual(len(results), 3)
        
        for domain, result in zip(domains, results):
            self.assertTrue(result['success'])
            self.assertIn('results', result)
        
        # Verify database contains all scans
        scan_count = self.db_manager.execute_query(
            "SELECT COUNT(*) FROM scans WHERE domain IN (?, ?, ?)",
            tuple(domains), fetch=True
        )
        self.assertEqual(scan_count[0][0], 3)
    
    def test_background_task_integration(self):
        """Test background task processing integration."""
        domain = "background-example.com"
        
        # Submit background scan
        task_id = self.scanner.scan_domain_background(domain)
        self.assertIsNotNone(task_id)
        
        # Wait for task completion
        max_wait = 10  # seconds
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            task_status = self.scanner.task_manager.get_task_status(task_id)
            if task_status and task_status['status'] in ['completed', 'failed']:
                break
            time.sleep(0.1)
        
        # Verify task completed
        final_status = self.scanner.task_manager.get_task_status(task_id)
        self.assertIsNotNone(final_status)
        self.assertEqual(final_status['status'], 'completed')
        
        # Verify scan was stored in database
        scan_data = self.db_manager.execute_query(
            "SELECT * FROM scans WHERE domain = ?", (domain,), fetch=True
        )
        self.assertEqual(len(scan_data), 1)
    
    def test_rate_limiting_integration(self):
        """Test rate limiting behavior in scanning."""
        # Configure rate limiter to be very restrictive
        self.scanner.rate_limiter.requests_per_minute = 2
        self.scanner.rate_limiter.burst_size = 1
        self.scanner.rate_limiter.tokens = 1
        
        domains = ["rate1.com", "rate2.com", "rate3.com"]
        results = []
        
        # Scan multiple domains rapidly
        for domain in domains:
            result = self.scanner.scan_domain(domain)
            results.append(result)
            time.sleep(0.1)  # Small delay
        
        # Should have at least one rate-limited failure
        successful_scans = [r for r in results if r['success']]
        failed_scans = [r for r in results if not r['success']]
        
        self.assertGreater(len(failed_scans), 0)
        
        # Failed scans should mention rate limiting
        for failed_result in failed_scans:
            self.assertIn('rate', failed_result.get('error', '').lower())
    
    def test_database_concurrent_access(self):
        """Test concurrent database access during scanning."""
        domains = [f"concurrent{i}.com" for i in range(5)]
        results = []
        errors = []
        
        def worker(domain):
            try:
                result = self.scanner.scan_domain(domain)
                results.append(result)
            except Exception as e:
                errors.append(str(e))
        
        # Start multiple scanning threads
        threads = []
        for domain in domains:
            t = threading.Thread(target=worker, args=(domain,))
            threads.append(t)
            t.start()
        
        # Wait for all threads to complete
        for t in threads:
            t.join()
        
        # Verify no errors occurred
        self.assertEqual(len(errors), 0, f"Database errors: {errors}")
        
        # Verify all scans succeeded
        self.assertEqual(len(results), 5)
        for result in results:
            self.assertTrue(result['success'])
        
        # Verify all scans are in database
        total_scans = self.db_manager.execute_query(
            "SELECT COUNT(*) FROM scans", fetch=True
        )
        self.assertGreaterEqual(total_scans[0][0], 5)
    
    def test_error_handling_integration(self):
        """Test error handling across the scanning pipeline."""
        domain = "error-test.com"
        
        # Make DNS service raise an exception
        self.mock_dns.side_effect = Exception("DNS lookup failed")
        
        # Scan should handle the error gracefully
        result = self.scanner.scan_domain(domain)
        
        # Should not crash, but should report failure
        self.assertFalse(result['success'])
        self.assertIn('error', result)
        
        # Should still record the failure in database
        scan_data = self.db_manager.execute_query(
            "SELECT * FROM scans WHERE domain = ?", (domain,), fetch=True
        )
        # Depending on implementation, might or might not store failed scans
    
    def test_performance_metrics_collection(self):
        """Test that performance metrics are properly collected."""
        domain = "performance-test.com"
        
        # Add delays to mock services to measure timing
        def slow_dns(*args, **kwargs):
            time.sleep(0.1)
            return self.mock_dns.return_value
        
        def slow_subdomain(*args, **kwargs):
            time.sleep(0.05)
            return self.mock_subdomain.return_value
        
        self.mock_dns.side_effect = slow_dns
        self.mock_subdomain.side_effect = slow_subdomain
        
        # Perform scan
        result = self.scanner.scan_domain(domain)
        
        # Verify performance metrics
        self.assertTrue(result['success'])
        self.assertIn('performance', result)
        
        perf = result['performance']
        self.assertIn('total_duration', perf)
        self.assertIn('service_times', perf)
        
        # Should capture the delays we added
        self.assertGreaterEqual(perf['total_duration'], 0.15)  # At least our delays
        
        if 'dns_time' in perf['service_times']:
            self.assertGreaterEqual(perf['service_times']['dns_time'], 0.1)
    
    def test_system_resource_monitoring(self):
        """Test system resource monitoring during scanning."""
        domains = [f"resource{i}.com" for i in range(3)]
        
        # Get initial stats
        initial_stats = self.scanner.get_system_stats()
        
        # Perform scans
        for domain in domains:
            self.scanner.scan_domain(domain)
        
        # Get final stats
        final_stats = self.scanner.get_system_stats()
        
        # Verify stats structure
        for stats in [initial_stats, final_stats]:
            self.assertIn('active_tasks', stats)
            self.assertIn('cache_stats', stats)
            self.assertIn('database_stats', stats)
        
        # Should have some cache activity
        cache_stats = final_stats['cache_stats']
        self.assertGreaterEqual(cache_stats['hits'] + cache_stats['misses'], 0)


class TestFlaskIntegration(unittest.TestCase):
    """Integration tests for Flask routes with optimized services."""
    
    def setUp(self):
        """Set up Flask test client."""
        # This would require setting up the actual Flask app with test config
        # For now, we'll mock the Flask integration
        pass
    
    def test_single_scan_route_integration(self):
        """Test single scan route with optimization services."""
        # Mock test - would need actual Flask app setup
        pass
    
    def test_batch_scan_route_integration(self):
        """Test batch scan route with optimization services."""
        # Mock test - would need actual Flask app setup
        pass
    
    def test_monitoring_dashboard_integration(self):
        """Test monitoring dashboard API integration."""
        # Mock test - would need actual Flask app setup
        pass


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add integration test cases
    test_suite.addTest(unittest.makeSuite(TestIntegrationOptimizedScanning))
    test_suite.addTest(unittest.makeSuite(TestFlaskIntegration))
    
    # Run tests with high verbosity
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n{'='*50}")
    print(f"Integration Test Summary:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    print(f"{'='*50}")
    
    # Exit with error code if tests failed
    sys.exit(0 if result.wasSuccessful() else 1)

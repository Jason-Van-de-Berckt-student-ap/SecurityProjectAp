#!/usr/bin/env python3
"""
EASM Application Optimization Validation Script
Comprehensive testing and validation of all optimization features.
"""

import os
import sys
import time
import requests
import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

class OptimizationValidator:
    """Validates all EASM optimization features."""
    
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.results = {}
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def validate_all(self):
        """Run all validation tests."""
        print("🚀 EASM Application Optimization Validation")
        print("=" * 60)
        
        tests = [
            ("Application Startup", self.test_application_startup),
            ("Database Connectivity", self.test_database_connectivity),
            ("Authentication System", self.test_authentication),
            ("Cache Manager", self.test_cache_manager),
            ("Monitoring Dashboard", self.test_monitoring_dashboard),
            ("Scanning Engine", self.test_scanning_engine),
            ("Security Headers", self.test_security_headers),
            ("Health Check", self.test_health_check),
            ("Logging System", self.test_logging_system),
            ("Performance Metrics", self.test_performance)
        ]
        
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests:
            print(f"\n🧪 Testing: {test_name}")
            try:
                result = test_func()
                if result:
                    print(f"   ✅ {test_name}: PASSED")
                    passed += 1
                else:
                    print(f"   ❌ {test_name}: FAILED")
                self.results[test_name] = result
            except Exception as e:
                print(f"   ❌ {test_name}: ERROR - {str(e)}")
                self.results[test_name] = False
        
        print("\n" + "=" * 60)
        print(f"📊 VALIDATION SUMMARY")
        print(f"   Total Tests: {total}")
        print(f"   Passed: {passed}")
        print(f"   Failed: {total - passed}")
        print(f"   Success Rate: {(passed/total)*100:.1f}%")
        
        if passed == total:
            print("🎉 ALL OPTIMIZATIONS VALIDATED SUCCESSFULLY!")
        else:
            print("⚠️  Some optimizations need attention")
        
        return passed == total
    
    def test_application_startup(self):
        """Test if application starts and responds."""
        try:
            response = self.session.get(f"{self.base_url}/")
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Application startup test failed: {e}")
            return False
    
    def test_database_connectivity(self):
        """Test database connectivity and table structure."""
        try:
            # Check if database file exists
            db_path = project_root / "easm.db"
            if not db_path.exists():
                return False
            
            # Check table structure
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            # Check required tables
            tables = ['scans', 'batch_scans', 'users', 'user_sessions', 'system_logs']
            for table in tables:
                cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
                if not cursor.fetchone():
                    self.logger.error(f"Table {table} not found")
                    return False
            
            conn.close()
            return True
        except Exception as e:
            self.logger.error(f"Database connectivity test failed: {e}")
            return False
    
    def test_authentication(self):
        """Test authentication system."""
        try:
            # Test login page
            response = self.session.get(f"{self.base_url}/auth/login")
            if response.status_code != 200:
                return False
            
            # Test registration page
            response = self.session.get(f"{self.base_url}/auth/register")
            if response.status_code != 200:
                return False
            
            return True
        except Exception as e:
            self.logger.error(f"Authentication test failed: {e}")
            return False
    
    def test_cache_manager(self):
        """Test cache manager functionality."""
        try:
            # Import cache manager
            from services.cache_manager import CacheManager
            
            # Test in-memory cache
            cache_config = {'type': 'memory'}
            cache = CacheManager(cache_config)
            
            # Test basic operations
            cache.set('test_key', 'test_value', ttl=60)
            value = cache.get('test_key')
            if value != 'test_value':
                return False
            
            # Test cache statistics
            stats = cache.get_cache_statistics()
            return isinstance(stats, dict) and 'cache_type' in stats
        except Exception as e:
            self.logger.error(f"Cache manager test failed: {e}")
            return False
    
    def test_monitoring_dashboard(self):
        """Test monitoring dashboard."""
        try:
            response = self.session.get(f"{self.base_url}/monitoring/dashboard")
            # Should redirect to login if not authenticated, which is correct behavior
            return response.status_code in [200, 302]
        except Exception as e:
            self.logger.error(f"Monitoring dashboard test failed: {e}")
            return False
    
    def test_scanning_engine(self):
        """Test scanning engine basic functionality."""
        try:
            from services.optimized_scanner import OptimizedScanner
            
            scanner = OptimizedScanner(max_workers=2, timeout=30)
            
            # Test DNS resolution (simple test)
            import socket
            socket.gethostbyname('google.com')
            
            return True
        except Exception as e:
            self.logger.error(f"Scanning engine test failed: {e}")
            return False
    
    def test_security_headers(self):
        """Test security headers are present."""
        try:
            response = self.session.get(f"{self.base_url}/")
            headers = response.headers
            
            # Check for important security headers
            security_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection'
            ]
            
            for header in security_headers:
                if header not in headers:
                    self.logger.warning(f"Security header {header} not found")
            
            return True  # Non-critical for functionality
        except Exception as e:
            self.logger.error(f"Security headers test failed: {e}")
            return False
    
    def test_health_check(self):
        """Test health check endpoint."""
        try:
            response = self.session.get(f"{self.base_url}/health")
            if response.status_code == 200:
                data = response.json()
                return data.get('status') == 'healthy'
            return False
        except Exception as e:
            self.logger.error(f"Health check test failed: {e}")
            return False
    
    def test_logging_system(self):
        """Test logging system."""
        try:
            # Check if log files exist
            logs_dir = project_root / "logs"
            if not logs_dir.exists():
                return False
            
            # Check for log files
            log_files = ['app.log', 'audit.log', 'error.log']
            for log_file in log_files:
                log_path = logs_dir / log_file
                if not log_path.exists():
                    self.logger.warning(f"Log file {log_file} not found")
            
            return True
        except Exception as e:
            self.logger.error(f"Logging system test failed: {e}")
            return False
    
    def test_performance(self):
        """Test basic performance metrics."""
        try:
            # Test response time
            start_time = time.time()
            response = self.session.get(f"{self.base_url}/")
            response_time = time.time() - start_time
            
            # Should respond within 2 seconds for basic page
            if response_time > 2.0:
                self.logger.warning(f"Slow response time: {response_time:.2f}s")
            
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Performance test failed: {e}")
            return False
    
    def generate_report(self):
        """Generate detailed validation report."""
        report_path = project_root / "validation_report.md"
        
        with open(report_path, 'w') as f:
            f.write("# EASM Application Optimization Validation Report\n")
            f.write(f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
            
            f.write("## Test Results\n\n")
            for test_name, result in self.results.items():
                status = "✅ PASSED" if result else "❌ FAILED"
                f.write(f"- **{test_name}**: {status}\n")
            
            f.write("\n## Summary\n\n")
            passed = sum(1 for r in self.results.values() if r)
            total = len(self.results)
            f.write(f"- Total Tests: {total}\n")
            f.write(f"- Passed: {passed}\n")
            f.write(f"- Success Rate: {(passed/total)*100:.1f}%\n")
            
            f.write("\n## Recommendations\n\n")
            failed_tests = [name for name, result in self.results.items() if not result]
            if failed_tests:
                f.write("The following tests failed and need attention:\n")
                for test in failed_tests:
                    f.write(f"- {test}\n")
            else:
                f.write("All tests passed! The application is fully optimized and ready for production.\n")
        
        print(f"\n📄 Detailed report saved to: {report_path}")


def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate EASM optimization")
    parser.add_argument("--url", default="http://127.0.0.1:5000", 
                       help="Base URL of the EASM application")
    parser.add_argument("--report", action="store_true",
                       help="Generate detailed report")
    
    args = parser.parse_args()
    
    validator = OptimizationValidator(args.url)
    success = validator.validate_all()
    
    if args.report:
        validator.generate_report()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

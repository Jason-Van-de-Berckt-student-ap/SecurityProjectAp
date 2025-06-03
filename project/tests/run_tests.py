#!/usr/bin/env python3
"""
Test runner for EASM optimization services.
Runs unit tests, integration tests, and performance benchmarks.
"""

import os
import sys
import unittest
import time
import argparse
import logging
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Test modules
from tests.test_optimization_services import *
from tests.test_integration import *


class ColoredTestResult(unittest.TextTestResult):
    """Test result class with colored output."""
    
    def __init__(self, stream, descriptions, verbosity):
        super().__init__(stream, descriptions, verbosity)
        self.success_count = 0
    
    def addSuccess(self, test):
        super().addSuccess(test)
        self.success_count += 1
        if self.verbosity > 1:
            self.stream.write(f"\033[92m✓ {test._testMethodName}\033[0m\n")
        else:
            self.stream.write('\033[92m.\033[0m')
        self.stream.flush()
    
    def addError(self, test, err):
        super().addError(test, err)
        if self.verbosity > 1:
            self.stream.write(f"\033[91m✗ {test._testMethodName} (ERROR)\033[0m\n")
        else:
            self.stream.write('\033[91mE\033[0m')
        self.stream.flush()
    
    def addFailure(self, test, err):
        super().addFailure(test, err)
        if self.verbosity > 1:
            self.stream.write(f"\033[91m✗ {test._testMethodName} (FAIL)\033[0m\n")
        else:
            self.stream.write('\033[91mF\033[0m')
        self.stream.flush()
    
    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        if self.verbosity > 1:
            self.stream.write(f"\033[93m- {test._testMethodName} (SKIP: {reason})\033[0m\n")
        else:
            self.stream.write('\033[93mS\033[0m')
        self.stream.flush()


class ColoredTestRunner(unittest.TextTestRunner):
    """Test runner with colored output."""
    
    resultclass = ColoredTestResult
    
    def run(self, test):
        result = super().run(test)
        
        # Print colored summary
        print(f"\n{'='*60}")
        if result.wasSuccessful():
            print(f"\033[92m✓ ALL TESTS PASSED\033[0m")
        else:
            print(f"\033[91m✗ SOME TESTS FAILED\033[0m")
        
        print(f"\033[94mTest Summary:\033[0m")
        print(f"  Total tests: {result.testsRun}")
        print(f"  \033[92mPassed: {result.success_count}\033[0m")
        print(f"  \033[91mFailed: {len(result.failures)}\033[0m")
        print(f"  \033[91mErrors: {len(result.errors)}\033[0m")
        print(f"  \033[93mSkipped: {len(result.skipped)}\033[0m")
        
        if result.testsRun > 0:
            success_rate = (result.success_count / result.testsRun) * 100
            print(f"  Success rate: {success_rate:.1f}%")
        
        print(f"{'='*60}")
        return result


def setup_logging(verbosity):
    """Set up logging configuration."""
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )


def run_unit_tests(verbosity=1):
    """Run unit tests for optimization services."""
    print(f"\033[94m{'='*60}\033[0m")
    print(f"\033[94mRunning Unit Tests\033[0m")
    print(f"\033[94m{'='*60}\033[0m")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestDatabaseManager,
        TestCacheManager,
        TestRateLimiter,
        TestBackgroundTaskManager,
        TestOptimizedScanner
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = ColoredTestRunner(verbosity=verbosity)
    return runner.run(suite)


def run_integration_tests(verbosity=1):
    """Run integration tests."""
    print(f"\033[94m{'='*60}\033[0m")
    print(f"\033[94mRunning Integration Tests\033[0m")
    print(f"\033[94m{'='*60}\033[0m")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add integration test classes
    test_classes = [
        TestIntegrationOptimizedScanning,
        TestFlaskIntegration
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = ColoredTestRunner(verbosity=verbosity)
    return runner.run(suite)


def run_performance_tests(verbosity=1):
    """Run performance benchmark tests."""
    print(f"\033[94m{'='*60}\033[0m")
    print(f"\033[94mRunning Performance Tests\033[0m")
    print(f"\033[94m{'='*60}\033[0m")
    
    try:
        from tests.test_performance import run_performance_benchmarks
        return run_performance_benchmarks(verbosity)
    except ImportError:
        print("\033[93mPerformance tests not available (test_performance.py not found)\033[0m")
        return True


def run_security_tests(verbosity=1):
    """Run security tests."""
    print(f"\033[94m{'='*60}\033[0m")
    print(f"\033[94mRunning Security Tests\033[0m")
    print(f"\033[94m{'='*60}\033[0m")
    
    try:
        from tests.test_security import run_security_tests
        return run_security_tests(verbosity)
    except ImportError:
        print("\033[93mSecurity tests not available (test_security.py not found)\033[0m")
        return True


def check_dependencies():
    """Check if all required dependencies are available."""
    print("Checking dependencies...")
    
    required_packages = [
        'redis',
        'sqlite3',
        'concurrent.futures',
        'threading',
        'json',
        'time',
        'unittest'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"  \033[92m✓ {package}\033[0m")
        except ImportError:
            print(f"  \033[91m✗ {package}\033[0m")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n\033[91mMissing packages: {', '.join(missing_packages)}\033[0m")
        print("Please install missing packages before running tests.")
        return False
    
    print("\033[92mAll dependencies available.\033[0m\n")
    return True


def generate_test_report(results, output_file=None):
    """Generate a test report."""
    if output_file is None:
        output_file = f"test_report_{int(time.time())}.txt"
    
    with open(output_file, 'w') as f:
        f.write("EASM Optimization Services Test Report\n")
        f.write("=" * 50 + "\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        for test_type, result in results.items():
            f.write(f"{test_type} Results:\n")
            f.write(f"  Tests run: {result.testsRun}\n")
            f.write(f"  Failures: {len(result.failures)}\n")
            f.write(f"  Errors: {len(result.errors)}\n")
            f.write(f"  Skipped: {len(result.skipped)}\n")
            
            if result.failures:
                f.write(f"\n  Failures:\n")
                for test, traceback in result.failures:
                    f.write(f"    - {test}: {traceback}\n")
            
            if result.errors:
                f.write(f"\n  Errors:\n")
                for test, traceback in result.errors:
                    f.write(f"    - {test}: {traceback}\n")
            
            f.write("\n")
    
    print(f"\033[94mTest report saved to: {output_file}\033[0m")


def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(description="Run EASM optimization tests")
    parser.add_argument('--unit', action='store_true', help='Run unit tests only')
    parser.add_argument('--integration', action='store_true', help='Run integration tests only')
    parser.add_argument('--performance', action='store_true', help='Run performance tests only')
    parser.add_argument('--security', action='store_true', help='Run security tests only')
    parser.add_argument('--all', action='store_true', help='Run all tests (default)')
    parser.add_argument('--verbose', '-v', action='count', default=1, help='Increase verbosity')
    parser.add_argument('--quiet', '-q', action='store_true', help='Minimal output')
    parser.add_argument('--report', help='Generate test report to file')
    parser.add_argument('--no-deps-check', action='store_true', help='Skip dependency check')
    
    args = parser.parse_args()
    
    # Set verbosity
    if args.quiet:
        verbosity = 0
    else:
        verbosity = args.verbose
    
    setup_logging(verbosity)
    
    # Check dependencies unless skipped
    if not args.no_deps_check and not check_dependencies():
        return 1
    
    # Determine which tests to run
    run_unit = args.unit or args.all or not any([args.unit, args.integration, args.performance, args.security])
    run_integration = args.integration or args.all
    run_performance = args.performance or args.all
    run_security = args.security or args.all
    
    # Run tests
    results = {}
    overall_success = True
    
    start_time = time.time()
    
    try:
        if run_unit:
            print("\n" + "="*60)
            print("UNIT TESTS")
            print("="*60)
            result = run_unit_tests(verbosity)
            results['Unit Tests'] = result
            overall_success &= result.wasSuccessful()
        
        if run_integration:
            print("\n" + "="*60)
            print("INTEGRATION TESTS")
            print("="*60)
            result = run_integration_tests(verbosity)
            results['Integration Tests'] = result
            overall_success &= result.wasSuccessful()
        
        if run_performance:
            print("\n" + "="*60)
            print("PERFORMANCE TESTS")
            print("="*60)
            success = run_performance_tests(verbosity)
            overall_success &= success
        
        if run_security:
            print("\n" + "="*60)
            print("SECURITY TESTS")
            print("="*60)
            success = run_security_tests(verbosity)
            overall_success &= success
        
    except KeyboardInterrupt:
        print("\n\033[93mTests interrupted by user.\033[0m")
        return 130
    except Exception as e:
        print(f"\n\033[91mUnexpected error during testing: {e}\033[0m")
        return 1
    
    # Calculate total time
    total_time = time.time() - start_time
    
    # Generate report if requested
    if args.report and results:
        generate_test_report(results, args.report)
    
    # Print final summary
    print(f"\n{'='*60}")
    print(f"\033[94mFINAL TEST SUMMARY\033[0m")
    print(f"{'='*60}")
    print(f"Total time: {total_time:.2f} seconds")
    
    if overall_success:
        print(f"\033[92m✓ ALL TESTS PASSED\033[0m")
        return 0
    else:
        print(f"\033[91m✗ SOME TESTS FAILED\033[0m")
        return 1


if __name__ == '__main__':
    sys.exit(main())

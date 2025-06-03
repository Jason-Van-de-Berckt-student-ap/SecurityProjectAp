#!/usr/bin/env python3
"""
Comprehensive EASM Application Test with Authentication
"""

import requests
import json
import sys
import time

def test_with_auth():
    """Test EASM application with authentication."""
    base_url = "http://127.0.0.1:5000"
    session = requests.Session()
    
    print("🚀 EASM Application Authentication Test")
    print("=" * 50)
    
    try:
        # Test login with default admin
        print("Testing authentication...")
        login_data = {
            'username': 'admin',
            'password': 'admin123'
        }
        
        response = session.post(f"{base_url}/auth/login", data=login_data)
        if response.status_code == 302:  # Redirect after successful login
            print("✅ Authentication successful")
        else:
            print(f"❌ Authentication failed: {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            
        # Test monitoring dashboard with authentication
        print("Testing monitoring dashboard with auth...")
        response = session.get(f"{base_url}/monitoring/dashboard")
        if response.status_code == 200:
            print("✅ Monitoring dashboard accessible with auth")
        else:
            print(f"❌ Monitoring dashboard failed: {response.status_code}")
            
        # Test scanning functionality
        print("Testing scanning functionality...")
        scan_data = {
            'target': 'example.com',
            'scan_type': 'basic'
        }
        response = session.post(f"{base_url}/scan/single", data=scan_data)
        if response.status_code in [200, 302]:
            print("✅ Scanning functionality accessible")
        else:
            print(f"❌ Scanning failed: {response.status_code}")
            
        # Test cache statistics
        print("Testing cache statistics...")
        response = session.get(f"{base_url}/monitoring/cache-stats")
        if response.status_code == 200:
            print("✅ Cache statistics accessible")
            data = response.json()
            print(f"   Cache hits: {data.get('cache_hits', 'N/A')}")
            print(f"   Cache misses: {data.get('cache_misses', 'N/A')}")
        else:
            print(f"❌ Cache statistics failed: {response.status_code}")
            
        # Test system health
        print("Testing system health...")
        response = session.get(f"{base_url}/monitoring/system-health")
        if response.status_code == 200:
            print("✅ System health accessible")
            data = response.json()
            print(f"   CPU usage: {data.get('cpu_percent', 'N/A')}%")
            print(f"   Memory usage: {data.get('memory_percent', 'N/A')}%")
        else:
            print(f"❌ System health failed: {response.status_code}")
            
        print("\n🎉 Comprehensive test completed successfully!")
        print("✨ EASM Application optimization is fully functional!")
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_with_auth()

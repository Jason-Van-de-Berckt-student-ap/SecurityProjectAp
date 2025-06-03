#!/usr/bin/env python3
"""
Quick EASM Application Test
"""

import requests
import json
import sys

def test_app():
    """Quick test of the EASM application."""
    base_url = "http://127.0.0.1:5000"
    
    print("🚀 Quick EASM Application Test")
    print("=" * 40)
    
    try:
        # Test main page
        print("Testing main page...")
        response = requests.get(base_url)
        if response.status_code == 200:
            print("✅ Main page accessible")
        else:
            print(f"❌ Main page failed: {response.status_code}")
            
        # Test health check
        print("Testing health check...")
        response = requests.get(f"{base_url}/health")
        if response.status_code == 200:
            print("✅ Health check passed")
            data = response.json()
            print(f"   Status: {data.get('status')}")
        else:
            print(f"❌ Health check failed: {response.status_code}")
            
        # Test authentication pages
        print("Testing authentication...")
        response = requests.get(f"{base_url}/auth/login")
        if response.status_code == 200:
            print("✅ Login page accessible")
        else:
            print(f"❌ Login page failed: {response.status_code}")
            
        # Test monitoring dashboard
        print("Testing monitoring dashboard...")
        response = requests.get(f"{base_url}/monitoring/dashboard")
        if response.status_code == 200:
            print("✅ Monitoring dashboard accessible")
        else:
            print(f"❌ Monitoring dashboard failed: {response.status_code}")
            
        print("\n🎉 Quick test completed successfully!")
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_app()

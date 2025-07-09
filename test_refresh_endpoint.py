#!/usr/bin/env python3
"""
Test script to verify the /refresh endpoint functionality
"""

import requests
import json
import sys

def test_refresh_endpoint():
    """Test the /refresh endpoint"""
    base_url = "https://localhost:8000"
    
    # Test parameters
    session_id = "test_session_123"
    
    print("Testing /refresh endpoint...")
    
    try:
        # Test /refresh endpoint
        refresh_url = f"{base_url}/refresh?sessionIdentifier={session_id}"
        print(f"Calling: {refresh_url}")
        
        # Make request with SSL verification disabled for self-signed cert
        response = requests.get(refresh_url, verify=False, timeout=10)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"Response Body: {response.text}")
        
        if response.status_code == 200:
            print("✓ /refresh endpoint is working")
            return True
        else:
            print(f"✗ /refresh endpoint failed with status {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError as e:
        print(f"✗ Connection error: {e}")
        print("Make sure the server is running with: cargo run")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_health_endpoint():
    """Test the /health endpoint to verify server is running"""
    base_url = "https://localhost:8000"
    
    print("Testing /health endpoint...")
    
    try:
        health_url = f"{base_url}/health"
        response = requests.get(health_url, verify=False, timeout=5)
        
        print(f"Health Status Code: {response.status_code}")
        if response.status_code == 200:
            print("✓ Server is running")
            return True
        else:
            print("✗ Server health check failed")
            return False
            
    except Exception as e:
        print(f"✗ Health check error: {e}")
        return False

if __name__ == "__main__":
    print("=== eID-Server Refresh Endpoint Test ===")
    
    # First check if server is running
    if not test_health_endpoint():
        print("\nPlease start the server first with: cargo run")
        sys.exit(1)
    
    print()
    
    # Test refresh endpoint
    if test_refresh_endpoint():
        print("\n✓ All tests passed!")
        sys.exit(0)
    else:
        print("\n✗ Tests failed!")
        sys.exit(1)
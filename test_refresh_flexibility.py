#!/usr/bin/env python3
"""
Test script to verify the /refresh endpoint flexibility with different parameter names
"""

import requests
import json
import sys
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_refresh_with_different_param_names():
    """Test the /refresh endpoint with different parameter names"""
    base_url = "https://localhost:8000"
    
    # Test different parameter names that real-world clients might use
    test_cases = [
        {"name": "SessionIdentifier", "param": "SessionIdentifier"},
        {"name": "sessionIdentifier", "param": "sessionIdentifier"},
        {"name": "sessionidentifier", "param": "sessionidentifier"},
        {"name": "session_identifier", "param": "session_identifier"},
        {"name": "session-identifier", "param": "session-identifier"},
        {"name": "session", "param": "session"},
        {"name": "Session", "param": "Session"},
        {"name": "ID", "param": "ID"},
        {"name": "id", "param": "id"},
    ]
    
    session_id = "test_session_123"
    
    print("=== Testing /refresh endpoint with different parameter names ===")
    
    for test_case in test_cases:
        print(f"\n--- Testing parameter: {test_case['name']} ---")
        
        try:
            # Test /refresh endpoint with different parameter names
            refresh_url = f"{base_url}/refresh?{test_case['param']}={session_id}"
            print(f"Calling: {refresh_url}")
            
            response = requests.get(refresh_url, verify=False, timeout=10)
            
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 404:
                print("✓ Parameter accepted (session not found is expected for test session)")
            elif response.status_code == 400:
                print("✗ Parameter not recognized")
                print(f"Response: {response.text}")
            else:
                print(f"Response: {response.text}")
                
        except Exception as e:
            print(f"✗ Error: {e}")

def test_health_endpoint():
    """Test the /health endpoint to verify server is running"""
    base_url = "https://localhost:8000"
    
    print("=== Testing server health ===")
    
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
    print("=== eID-Server Refresh Parameter Flexibility Test ===")
    
    # First check if server is running
    if not test_health_endpoint():
        print("\nPlease start the server first with: cargo run")
        sys.exit(1)
    
    print()
    
    # Test refresh endpoint with different parameter names
    test_refresh_with_different_param_names()
    
    print("\n=== Test completed ===")
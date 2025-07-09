#!/usr/bin/env python3
"""
Debug test script for the /refresh endpoint
"""

import requests
import json
import sys
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_refresh_with_different_params():
    """Test the /refresh endpoint with different parameter formats"""
    base_url = "https://localhost:8000"
    
    test_cases = [
        # Test case 1: Query parameter
        {
            "name": "Query parameter",
            "url": f"{base_url}/refresh?sessionIdentifier=test_session_123",
            "method": "GET"
        },
        # Test case 2: Different parameter name
        {
            "name": "Different parameter case",
            "url": f"{base_url}/refresh?sessionidentifier=test_session_123",
            "method": "GET"
        },
        # Test case 3: No parameters
        {
            "name": "No parameters",
            "url": f"{base_url}/refresh",
            "method": "GET"
        },
        # Test case 4: Empty parameter
        {
            "name": "Empty parameter",
            "url": f"{base_url}/refresh?sessionIdentifier=",
            "method": "GET"
        }
    ]
    
    for test_case in test_cases:
        print(f"\n--- Testing: {test_case['name']} ---")
        print(f"URL: {test_case['url']}")
        
        try:
            response = requests.get(test_case['url'], verify=False, timeout=10)
            
            print(f"Status Code: {response.status_code}")
            print(f"Response Headers: {dict(response.headers)}")
            print(f"Response Body: {response.text}")
            
            # Try to determine what the error might be
            if response.status_code == 400:
                print("→ This suggests BAD_REQUEST - likely missing/empty session identifier")
            elif response.status_code == 404:
                print("→ This suggests NOT_FOUND - session doesn't exist in session manager")
            elif response.status_code == 500:
                print("→ This suggests INTERNAL_SERVER_ERROR - server-side issue")
            elif response.status_code == 200:
                print("→ SUCCESS!")
                
        except Exception as e:
            print(f"Error: {e}")

def test_other_endpoints():
    """Test other endpoints to ensure server is working"""
    base_url = "https://localhost:8000"
    
    endpoints = [
        "/health",
        "/eIDService/getServerInfo"
    ]
    
    print("\n=== Testing other endpoints ===")
    for endpoint in endpoints:
        url = f"{base_url}{endpoint}"
        print(f"\nTesting: {url}")
        
        try:
            response = requests.get(url, verify=False, timeout=5)
            print(f"Status: {response.status_code}")
            if response.status_code == 200:
                print("✓ Working")
            else:
                print("✗ Not working")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    print("=== eID-Server Refresh Endpoint Debug Test ===")
    
    # Test other endpoints first
    test_other_endpoints()
    
    print("\n" + "="*50)
    
    # Test refresh endpoint with different parameters
    test_refresh_with_different_params()
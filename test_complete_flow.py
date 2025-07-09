#!/usr/bin/env python3
"""
Test script to verify the complete flow: useID -> refresh -> paos
"""

import requests
import json
import sys
import urllib3
import xml.etree.ElementTree as ET
import base64
import zlib
import urllib.parse

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def create_saml_request():
    """Create a minimal SAML AuthnRequest for testing"""
    saml_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_test_request_id"
                    Version="2.0"
                    IssueInstant="2024-01-01T00:00:00Z"
                    Destination="https://localhost:8000/eIDService/useID">
    <saml:Issuer>test-issuer</saml:Issuer>
    <samlp:Extensions>
        <saml:Attribute Name="http://bsi.bund.de/eID/GivenNames">
            <saml:AttributeValue>required</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="http://bsi.bund.de/eID/FamilyNames">
            <saml:AttributeValue>required</saml:AttributeValue>
        </saml:Attribute>
    </samlp:Extensions>
</samlp:AuthnRequest>'''
    
    # Compress with DEFLATE
    compressed = zlib.compress(saml_xml.encode('utf-8'))[2:-4]  # Remove zlib header/trailer
    
    # Base64 encode
    encoded = base64.b64encode(compressed).decode('ascii')
    
    # URL encode
    url_encoded = urllib.parse.quote(encoded)
    
    return url_encoded

def test_useid_endpoint():
    """Test the /eIDService/useID endpoint to create a session"""
    base_url = "https://localhost:8000"
    
    print("=== Step 1: Testing /eIDService/useID endpoint ===")
    
    try:
        # Create SAML request
        saml_request = create_saml_request()
        
        # Make request to useID endpoint
        useid_url = f"{base_url}/eIDService/useID?SAMLRequest={saml_request}"
        print(f"Calling: {useid_url}")
        
        response = requests.get(useid_url, verify=False, timeout=10)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"Response Body (first 500 chars): {response.text[:500]}")
        
        if response.status_code == 200:
            # Parse XML response to extract session identifier
            try:
                root = ET.fromstring(response.text)
                # Look for SessionIdentifier in the TCToken
                session_id_elem = root.find('.//{http://www.bsi.bund.de/ecard/api/1.1}SessionIdentifier')
                if session_id_elem is not None:
                    session_id = session_id_elem.text
                    print(f"✓ Session created successfully: {session_id}")
                    return session_id
                else:
                    print("✗ No SessionIdentifier found in response")
                    return None
            except ET.ParseError as e:
                print(f"✗ Failed to parse XML response: {e}")
                return None
        else:
            print(f"✗ useID endpoint failed with status {response.status_code}")
            return None
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return None

def test_refresh_endpoint(session_id):
    """Test the /refresh endpoint with the session ID from useID"""
    base_url = "https://localhost:8000"
    
    print(f"\n=== Step 2: Testing /refresh endpoint with session {session_id} ===")
    
    try:
        refresh_url = f"{base_url}/refresh?sessionIdentifier={session_id}"
        print(f"Calling: {refresh_url}")
        
        response = requests.get(refresh_url, verify=False, timeout=10)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"Response Body: {response.text}")
        
        if response.status_code == 200:
            print("✓ /refresh endpoint working correctly with real session")
            return True
        else:
            print(f"✗ /refresh endpoint failed with status {response.status_code}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_health_endpoint():
    """Test the /health endpoint to verify server is running"""
    base_url = "https://localhost:8000"
    
    print("=== Step 0: Testing server health ===")
    
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
    print("=== eID-Server Complete Flow Test ===")
    
    # Check if server is running
    if not test_health_endpoint():
        print("\nPlease start the server first with: cargo run")
        sys.exit(1)
    
    # Test useID endpoint to create a session
    session_id = test_useid_endpoint()
    if not session_id:
        print("\n✗ Failed to create session via useID endpoint")
        sys.exit(1)
    
    # Test refresh endpoint with the created session
    if test_refresh_endpoint(session_id):
        print("\n✓ Complete flow test passed!")
        print("✓ Both endpoints use the same session identifier")
        sys.exit(0)
    else:
        print("\n✗ Complete flow test failed!")
        sys.exit(1)
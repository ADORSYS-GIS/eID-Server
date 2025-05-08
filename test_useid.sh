#!/bin/bash

# Make sure the server is running before executing this script
# cargo run

# Create a temporary file for the SOAP request
SOAP_REQUEST='<?xml version="1.0" encoding="UTF-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Body><useID><UseOperations><UseOperation id="test_operation"/></UseOperations><PSK>test_psk</PSK></useID></soap:Body></soap:Envelope>'

# Save to temporary file
echo -n "$SOAP_REQUEST" > /tmp/soap_request.xml

# Send request with curl
echo "Sending useID request to eID Server..."
curl -X POST \
     -H "Content-Type: application/soap+xml" \
     --data @/tmp/soap_request.xml \
     http://localhost:3000/eIDService/useID

# Clean up
rm /tmp/soap_request.xml

echo -e "\n\nDone!"
#!/bin/bash

# Make sure the server is running before executing this script
# cargo run

# Create a temporary file for the SOAP request
SOAP_REQUEST='    <?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope
          xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
          xmlns:eid="http://bsi.bund.de/eID/">
          <soapenv:Body>
            <eid:useIDRequest>
              <eid:UseOperations>
                <eid:DocumentType>REQUIRED</eid:DocumentType>
                <eid:IssuingState>REQUIRED</eid:IssuingState>
                <eid:DateOfExpiry>REQUIRED</eid:DateOfExpiry>
                <eid:GivenNames>REQUIRED</eid:GivenNames>
                <eid:FamilyNames>REQUIRED</eid:FamilyNames>
                <eid:ArtisticName>ALLOWED</eid:ArtisticName>
                <eid:AcademicTitle>ALLOWED</eid:AcademicTitle>
                <eid:DateOfBirth>REQUIRED</eid:DateOfBirth>
                <eid:PlaceOfBirth>REQUIRED</eid:PlaceOfBirth>
                <eid:Nationality>REQUIRED</eid:Nationality>
                <eid:BirthName>REQUIRED</eid:BirthName>
                <eid:PlaceOfResidence>REQUIRED</eid:PlaceOfResidence>
                <eid:CommunityID>PROHIBITED</eid:CommunityID>
                <eid:ResidencePermitI>PROHIBITED</eid:ResidencePermitI>
                <eid:RestrictedID>REQUIRED</eid:RestrictedID>
                <eid:AgeVerification>REQUIRED</eid:AgeVerification>
                <eid:PlaceVerification>REQUIRED</eid:PlaceVerification>
              </eid:UseOperations>
              <eid:AgeVerificationRequest>
                <eid:Age>18</eid:Age>
              </eid:AgeVerificationRequest>
              <eid:PlaceVerificationRequest>
                <eid:CommunityID>027605</eid:CommunityID>
              </eid:PlaceVerificationRequest>
              <eid:TransactionAttestationRequest>
                <eid:TransactionAttestationFormat>http://bsi.bund.de/eID/ExampleAttestationFormat</eid:TransactionAttestationFormat>
                <eid:TransactionContext>id599456-df</eid:TransactionContext>
              </eid:TransactionAttestationRequest>
              <eid:LevelOfAssuranceRequest>http://bsi.bund.de/eID/LoA/hoch</eid:LevelOfAssuranceRequest>
              <eid:EIDTypeRequest>
                <eid:SECertified>ALLOWED</eid:SECertified>
                <eid:SEEndorsed>ALLOWED</eid:SEEndorsed>
              </eid:EIDTypeRequest>
            </eid:useIDRequest>
          </soapenv:Body>
        </soapenv:Envelope>'

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
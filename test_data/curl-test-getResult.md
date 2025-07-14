# Testing the getResult Endpoint with curl

This document provides examples of how to test the `getResult` endpoint using curl.

## Prerequisites

1. Start the eID-Server:
```bash
cargo run
```

2. The server should be running on `https://localhost:3000` (or your configured port)

## Basic getResult Request

Here's how to test the getResult endpoint with curl:

```bash
curl -X POST https://localhost:3000/eIDService/getResult \
  -H "Content-Type: application/soap+xml; charset=utf-8" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
  <soapenv:Header />
  <soapenv:Body>
    <eid:getResultRequest>
      <eid:Session>
        <eid:ID>1752482652885197768-a11de5af-fd63-4a9a-804d-85d9e0bdb05e</eid:ID>
      </eid:Session>
      <eid:RequestCounter>1</eid:RequestCounter>
    </eid:getResultRequest>
  </soapenv:Body>
</soapenv:Envelope>' \
  --insecure
```

## Complete Testing Flow

To properly test getResult, you need to follow this sequence:

### 1. First, create a session with useID

```bash
curl -X POST https://localhost:3000/eIDService/useID \
  -H "Content-Type: application/soap+xml; charset=utf-8" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
  <soapenv:Header />
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
        <eid:BirthName>PROHIBITED</eid:BirthName>
        <eid:PlaceOfResidence>REQUIRED</eid:PlaceOfResidence>
        <eid:CommunityID>REQUIRED</eid:CommunityID>
        <eid:ResidencePermitID>REQUIRED</eid:ResidencePermitID>
        <eid:RestrictedID>REQUIRED</eid:RestrictedID>
        <eid:AgeVerification>REQUIRED</eid:AgeVerification>
        <eid:PlaceVerification>REQUIRED</eid:PlaceVerification>
      </eid:UseOperations>
      <eid:AgeVerificationRequest>
        <eid:Age>18</eid:Age>
      </eid:AgeVerificationRequest>
      <eid:PlaceVerificationRequest>
        <eid:CommunityID>12345</eid:CommunityID>
      </eid:PlaceVerificationRequest>
    </eid:useIDRequest>
  </soapenv:Body>
</soapenv:Envelope>' \
  --insecure
```

### 2. Extract the session ID from the useID response

The response will contain a session ID like:
```xml
<eid:Session>
  <eid:ID>1234567890-abcd-efgh-ijkl-mnopqrstuvwx</eid:ID>
</eid:Session>
```

### 3. Test getResult with "No Result Yet" (authentication not completed)

```bash
curl -X POST https://localhost:3000/eIDService/getResult \
  -H "Content-Type: application/soap+xml; charset=utf-8" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
  <soapenv:Header />
  <soapenv:Body>
    <eid:getResultRequest>
      <eid:Session>
        <eid:ID>1752482389457325786-8f14e227-2936-4594-a27c-4fbe5fd992b2</eid:ID>
      </eid:Session>
      <eid:RequestCounter>1</eid:RequestCounter>
    </eid:getResultRequest>
  </soapenv:Body>
</soapenv:Envelope>' \
  --insecure
```

This should return HTTP 202 (Accepted) with "Result not available yet. Try again later."

### 4. Test with invalid session ID

```bash
curl -X POST https://localhost:3000/eIDService/getResult \
  -H "Content-Type: application/soap+xml; charset=utf-8" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
  <soapenv:Header />
  <soapenv:Body>
    <eid:getResultRequest>
      <eid:Session>
        <eid:ID>invalid-session-id</eid:ID>
      </eid:Session>
      <eid:RequestCounter>1</eid:RequestCounter>
    </eid:getResultRequest>
  </soapenv:Body>
</soapenv:Envelope>' \
  --insecure
```

This should return HTTP 400 (Bad Request) with "Session expired or already used and deleted."

### 5. Test with invalid request counter

```bash
curl -X POST https://localhost:3000/eIDService/getResult \
  -H "Content-Type: application/soap+xml; charset=utf-8" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
  <soapenv:Header />
  <soapenv:Body>
    <eid:getResultRequest>
      <eid:Session>
        <eid:ID>1752150959721741310-7e60d006-9ebf-4fd6-89b2-ae4b8c3363ae</eid:ID>
      </eid:Session>
      <eid:RequestCounter>5</eid:RequestCounter>
    </eid:getResultRequest>
  </soapenv:Body>
</soapenv:Envelope>' \
  --insecure
```

This should return HTTP 400 (Bad Request) with "RequestCounter is invalid or reused."

## Expected Responses

### Success Response (when authentication is completed)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/" xmlns:dss="urn:oasis:names:tc:dss:1.0:core:schema">
  <soapenv:Header/>
  <soapenv:Body>
    <eid:getResultResponse>
      <eid:PersonalData>
        <!-- Personal data from eID document -->
      </eid:PersonalData>
      <eid:OperationsAllowedByUser>
        <!-- Operations that were allowed -->
      </eid:OperationsAllowedByUser>
      <dss:Result>
        <ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</ResultMajor>
      </dss:Result>
    </eid:getResultResponse>
  </soapenv:Body>
</soapenv:Envelope>
```

### Error Responses
- **No Result Yet**: HTTP 202 with error message
- **Invalid Session**: HTTP 400 with error message  
- **Invalid Counter**: HTTP 400 with error message
- **Invalid Content Type**: HTTP 400 with error message

## Notes

1. Use `--insecure` flag with curl if testing with self-signed certificates
2. The session ID must be obtained from a previous `useID` call
3. The RequestCounter must be incremented for each `getResult` call within the same session
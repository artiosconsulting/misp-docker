#!/bin/bash

# MISP API Sample Curl Commands
# These examples show how to use MISP's REST API for threat intelligence operations

# Configuration
MISP_URL="https://localhost:8443"
API_KEY="secret_key"  # From your .env file
ACCEPT_HEADER="application/json"
CONTENT_TYPE="application/json"

echo "=== MISP API Sample Commands ==="
echo "MISP URL: $MISP_URL"
echo "Note: Make sure MISP is running with 'docker compose up -d'"
echo

# 1. Test API connectivity
echo "1. Testing API connectivity..."
echo "Command:"
echo "curl -k -H \"Authorization: $API_KEY\" -H \"Accept: $ACCEPT_HEADER\" \"$MISP_URL/servers/getPyMISPVersion.json\""
echo

# 2. Create an event for website analysis
echo "2. Creating an event for website analysis..."
cat << 'EOF'
curl -k -X POST \
  -H "Authorization: secret_key" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://localhost:8443/events/add" \
  -d '{
    "Event": {
      "info": "Website Security Analysis - Suspicious Domain",
      "threat_level_id": "2",
      "analysis": "1",
      "distribution": "1",
      "published": false
    }
  }'
EOF
echo
echo

# 3. Add a URL attribute to scan
echo "3. Adding a URL attribute for analysis..."
cat << 'EOF'
curl -k -X POST \
  -H "Authorization: secret_key" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://localhost:8443/attributes/add/1" \
  -d '{
    "Attribute": {
      "type": "url",
      "category": "Network activity",
      "value": "http://suspicious-website.example.com",
      "comment": "Potentially malicious website for analysis",
      "distribution": "1",
      "to_ids": true
    }
  }'
EOF
echo
echo

# 4. Add a domain attribute
echo "4. Adding a domain attribute..."
cat << 'EOF'
curl -k -X POST \
  -H "Authorization: secret_key" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://localhost:8443/attributes/add/1" \
  -d '{
    "Attribute": {
      "type": "domain",
      "category": "Network activity", 
      "value": "https://niscarea.com/in.php",
      "comment": "Suspicious domain detected during website scan",
      "distribution": "1",
      "to_ids": true
    }
  }'
EOF
echo
echo

# 5. Add an IP address attribute
echo "5. Adding an IP address attribute..."
cat << 'EOF'
curl -k -X POST \
  -H "Authorization: secret_key" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://localhost:8443/attributes/add/1" \
  -d '{
    "Attribute": {
      "type": "ip-dst",
      "category": "Network activity",
      "value": "192.0.2.100",
      "comment": "Malicious IP hosting the suspicious website",
      "distribution": "1",
      "to_ids": true
    }
  }'
EOF
echo
echo

# 6. Search for existing threats related to a domain
echo "6. Searching for existing threats related to a domain..."
cat << 'EOF'
curl -k -X POST \
  -H "Authorization: secret_key" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://localhost:8443/attributes/restSearch" \
  -d '{
    "returnFormat": "json",
    "type": "domain",
    "value": "example.com",
    "limit": 10
  }'
EOF
echo
echo

# 7. Get all events (limit to recent ones)
echo "7. Getting recent events..."
cat << 'EOF'
curl -k -X GET \
  -H "Authorization: secret_key" \
  -H "Accept: application/json" \
  "https://localhost:8443/events/index/limit:10"
EOF
echo
echo

# 8. Enrich a URL using MISP modules (if modules are running)
echo "8. Enriching a URL using MISP modules..."
cat << 'EOF'
curl -k -X POST \
  -H "Authorization: secret_key" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://localhost:8443/modules/query/expansion/url" \
  -d '{
    "module": "virustotal",
    "attribute": {
      "type": "url",
      "value": "http://suspicious-website.example.com"
    }
  }'
EOF
echo
echo

# 9. Get MISP statistics
echo "9. Getting MISP statistics..."
cat << 'EOF'
curl -k -X GET \
  -H "Authorization: secret_key" \
  -H "Accept: application/json" \
  "https://localhost:8443/events/stats"
EOF
echo
echo

# 10. Website reputation check using external modules
echo "10. Website reputation check (example with URLhaus module)..."
cat << 'EOF'
curl -k -X POST \
  -H "Authorization: secret_key" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://localhost:8443/modules/query/expansion/url" \
  -d '{
    "module": "urlhaus",
    "attribute": {
      "type": "url", 
      "value": "http://example.com/suspicious-path"
    }
  }'
EOF
echo
echo

echo "=== Usage Instructions ==="
echo "1. Start MISP: docker compose up -d"
echo "2. Wait for all services to be healthy (check with: docker compose ps)"
echo "3. Access MISP web interface: https://localhost:8443"
echo "4. Login with: admin@ctem.com / SuperSecret"
echo "5. Get your real API key from: Administration -> List Users -> View -> Auth Keys"
echo "6. Replace the API key in these commands with your real one"
echo "7. Run individual curl commands as needed"
echo
echo "=== Security Notes ==="
echo "- The -k flag ignores SSL certificate errors (for self-signed certs)"
echo "- Replace example.com and suspicious URLs with actual targets"
echo "- Always use HTTPS in production"
echo "- Keep your API key secure and rotate it regularly"
echo
echo "=== Common Response Codes ==="
echo "- 200: Success"
echo "- 401: Unauthorized (check API key)"
echo "- 403: Forbidden (insufficient permissions)"
echo "- 404: Not found"
echo "- 500: Server error"

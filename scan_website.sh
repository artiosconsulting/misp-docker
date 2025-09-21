#!/bin/bash

# Quick MISP Website Scanner
# Usage: ./scan_website.sh <url_or_domain>

if [ $# -eq 0 ]; then
    echo "Usage: $0 <url_or_domain>"
    echo "Example: $0 https://niscarea.com/in.php"
    echo "Example: $0 https://niscarea.com/in.php"
    exit 1
fi

TARGET=$1
MISP_URL="https://localhost:8443"
API_KEY="secret_key"

echo "=== MISP Website Scanner ==="
echo "Target: $TARGET"
echo "MISP Instance: $MISP_URL"
echo

# Function to make API calls
make_api_call() {
    local method=$1
    local endpoint=$2
    local data=$3
    
    if [ -n "$data" ]; then
        curl -k -s -X $method \
            -H "Authorization: $API_KEY" \
            -H "Accept: application/json" \
            -H "Content-Type: application/json" \
            "$MISP_URL$endpoint" \
            -d "$data"
    else
        curl -k -s -X $method \
            -H "Authorization: $API_KEY" \
            -H "Accept: application/json" \
            "$MISP_URL$endpoint"
    fi
}

# Test connectivity first
echo "1. Testing MISP connectivity..."
response=$(make_api_call GET "/servers/getPyMISPVersion.json")
if echo "$response" | grep -q "version"; then
    echo "✓ MISP is accessible"
else
    echo "✗ Cannot connect to MISP. Make sure it's running with: docker compose up -d"
    exit 1
fi

# Determine if input is URL or domain
if [[ $TARGET == http* ]]; then
    ATTR_TYPE="url"
    CATEGORY="Network activity"
    echo "2. Detected URL format"
else
    ATTR_TYPE="domain"
    CATEGORY="Network activity"
    echo "2. Detected domain format"
fi

# Create an event for this scan
echo "3. Creating new event for analysis..."
event_data='{
    "Event": {
        "info": "Website Security Scan - '"$TARGET"'",
        "threat_level_id": "3",
        "analysis": "1",
        "distribution": "1",
        "published": false
    }
}'

event_response=$(make_api_call POST "/events/add" "$event_data")
event_id=$(echo "$event_response" | grep -o '"id":[[:space:]]*"[0-9]*"' | grep -o '[0-9]*')

if [ -n "$event_id" ]; then
    echo "✓ Created event ID: $event_id"
else
    echo "✗ Failed to create event"
    echo "Response: $event_response"
    exit 1
fi

# Add the target as an attribute
echo "4. Adding target as attribute..."
attr_data='{
    "Attribute": {
        "type": "'"$ATTR_TYPE"'",
        "category": "'"$CATEGORY"'",
        "value": "'"$TARGET"'",
        "comment": "Target for website security analysis",
        "distribution": "1",
        "to_ids": true
    }
}'

attr_response=$(make_api_call POST "/attributes/add/$event_id" "$attr_data")
if echo "$attr_response" | grep -q '"saved":true'; then
    echo "✓ Added $ATTR_TYPE attribute: $TARGET"
else
    echo "✗ Failed to add attribute"
    echo "Response: $attr_response"
fi

# Search for existing intelligence on this target
echo "5. Searching for existing threat intelligence..."
search_data='{
    "returnFormat": "json",
    "type": "'"$ATTR_TYPE"'",
    "value": "'"$TARGET"'",
    "limit": 5
}'

search_response=$(make_api_call POST "/attributes/restSearch" "$search_data")
threat_count=$(echo "$search_response" | grep -o '"Attribute"' | wc -l | tr -d ' ')

if [ "$threat_count" -gt 0 ]; then
    echo "⚠️  Found $threat_count existing threat intelligence records for $TARGET"
    echo "   This target may be malicious!"
else
    echo "ℹ️  No existing threat intelligence found for $TARGET"
fi

# Try to enrich with external modules (if available)
echo "6. Attempting enrichment with external modules..."
enrich_data='{
    "attribute": {
        "type": "'"$ATTR_TYPE"'",
        "value": "'"$TARGET"'"
    }
}'

# Try URLhaus module
urlhaus_response=$(make_api_call POST "/modules/query/expansion/urlhaus" "$enrich_data" 2>/dev/null)
if echo "$urlhaus_response" | grep -q "results"; then
    echo "✓ URLhaus enrichment successful"
else
    echo "ℹ️  URLhaus enrichment not available or no results"
fi

echo
echo "=== Scan Results Summary ==="
echo "Target: $TARGET"
echo "Event ID: $event_id"
echo "Threat Records Found: $threat_count"
echo "View in MISP: $MISP_URL/events/view/$event_id"
echo
echo "=== Next Steps ==="
echo "1. Visit the MISP web interface: $MISP_URL"
echo "2. Review the created event for detailed analysis"
echo "3. Add more attributes (IPs, hashes, etc.) as discovered"
echo "4. Set up feeds for automated threat intelligence updates"
echo

# Optional: Show the raw event data
read -p "Show raw event data? (y/N): " show_raw
if [[ $show_raw =~ ^[Yy]$ ]]; then
    echo
    echo "=== Raw Event Data ==="
    make_api_call GET "/events/view/$event_id.json" | python3 -m json.tool 2>/dev/null || cat
fi

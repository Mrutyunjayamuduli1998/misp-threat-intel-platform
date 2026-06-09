#!/bin/bash
read -sp "Paste API key: " APIKEY
echo ""
read -p "Search value: " QUERY
curl -k -s -H "Authorization: $APIKEY" -H "Content-Type: application/json" -H "Accept: application/json" -d "{\"returnFormat\":\"json\",\"value\":\"$QUERY\",\"limit\":10}" https://localhost/attributes/restSearch | python3 -m json.tool

#!/bin/bash

# Lark Messager API Examples
# Make sure the server is running on localhost:8080

BASE_URL="http://localhost:8080"

echo "=== Lark Messager API Examples ==="
echo

# Health check
echo "1. Health Check:"
curl -s "$BASE_URL/health" | jq .
echo

# User login (you need to create a user first via database)
echo "2. User Login:"
echo "Note: You need to create a user in the database first"
echo "Example command to create user (run in database):"
echo "INSERT INTO users (id, username, password_hash, created_at, updated_at) VALUES ('01234567-89ab-cdef-0123-456789abcdef', 'admin', '\$argon2id\$v=19\$m=19456,t=2,p=1\$...\$...', datetime('now'), datetime('now'));"
echo

read -p "Enter username: " USERNAME
read -s -p "Enter password: " PASSWORD
echo

LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"$USERNAME\", \"password\": \"$PASSWORD\"}")

echo "Login response:"
echo "$LOGIN_RESPONSE" | jq .

# Extract token if login successful
TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token // empty')

if [ -z "$TOKEN" ]; then
    echo "Login failed. Cannot proceed with authenticated requests."
    exit 1
fi

echo
echo "Successfully logged in. Token: ${TOKEN:0:20}..."
echo

# Verify recipient
echo "3. Verify Recipient:"
curl -s -X POST "$BASE_URL/recipients/verify" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient": "test@example.com",
    "recipient_type": "email"
  }' | jq .
echo

# Send message to user (will likely fail with invalid Lark credentials)
echo "4. Send Message to User:"
echo "Note: This will likely fail if Lark credentials are not properly configured"
curl -s -X POST "$BASE_URL/messages/send" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient": "test@example.com",
    "message": "Hello from Lark Messager API!",
    "recipient_type": "email"
  }' | jq .
echo

# Send message to group using chat_id
echo "5a. Send Message to Group (using chat_id):"
echo "Note: This will likely fail if Lark credentials are not properly configured"
curl -s -X POST "$BASE_URL/messages/send-group" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient": "oc_test_chat_id",
    "message": "Hello group from Lark Messager API!",
    "recipient_type": "chat_id"
  }' | jq .
echo

# Send message to group using chat name
echo "5b. Send Message to Group (using chat name):"
echo "Note: This will likely fail if Lark credentials are not properly configured"
curl -s -X POST "$BASE_URL/messages/send-group" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient": "技术讨论群",
    "message": "Hello group from Lark Messager API!",
    "recipient_type": "chat_name"
  }' | jq .
echo

# Create API key (requires admin permissions)
echo "6. Create API Key (requires admin permissions):"
echo "Note: This will likely fail unless the user has admin permissions"
curl -s -X POST "$BASE_URL/auth/api-keys" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test API Key",
    "permissions": "send_messages"
  }' | jq .
echo

# Test with invalid authentication
echo "7. Test Unauthorized Request:"
curl -s -X POST "$BASE_URL/messages/send" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient": "test@example.com",
    "message": "This should fail"
  }' | jq .
echo

# Test with API key (if you have one)
echo "8. Test with API Key:"
echo "If you have an API key, you can test it like this:"
echo "curl -H 'X-API-Key: your-api-key' -X POST '$BASE_URL/messages/send' -d '{...}'"
echo

echo "=== Examples completed ==="
#!/bin/bash

# Test script for Lark Messager
# This script runs all tests using the existing MySQL database

set -e

# Check if TEST_DATABASE_URL is set
if [ -z "$TEST_DATABASE_URL" ]; then
    echo "Warning: TEST_DATABASE_URL not set. Using default configuration."
    echo "Please set TEST_DATABASE_URL environment variable to point to your test database."
    echo "Example: export TEST_DATABASE_URL='mysql://user:password@localhost:3306/test_lark_messager'"
    echo ""
fi

echo "Running tests..."
cargo test

echo "Tests completed!"
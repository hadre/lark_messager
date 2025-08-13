#!/bin/bash

# Test script for Lark Messager
# This script starts a test MySQL database and runs all tests

set -e

echo "Starting test MySQL database..."
docker-compose -f docker-compose.test.yml up -d test-mysql

echo "Waiting for MySQL to be ready..."
until docker exec $(docker-compose -f docker-compose.test.yml ps -q test-mysql) mysqladmin ping -h "localhost" --silent; do
    echo "Waiting for MySQL..."
    sleep 2
done

echo "MySQL is ready!"

# Set test database URL
export TEST_DATABASE_URL="mysql://root:password@localhost:3307/test_lark_messager"

echo "Running tests..."
cargo test

echo "Cleaning up..."
docker-compose -f docker-compose.test.yml down

echo "Tests completed!"
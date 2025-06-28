#!/bin/bash

# Eden Core Test Runner
# Runs all tests from the tests directory

set -e

echo "Running Eden Core Tests from tests directory..."
echo "=================================================="

# Change to project root
cd "$(dirname "$0")/.."

# Build eden binary for integration tests
echo "Building eden binary..."
if [ ! -d "./bin" ]; then
    mkdir -p ./bin
fi
cd cmd/eden && go build -o ../../bin/eden . && cd ../..

echo ""
echo "Running main CLI tests..."
cd tests/main && go test -v ./... && cd ../..

echo ""
echo "Running integration tests..."
cd tests && go test -v -run TestIntegration ./... && cd ..

echo ""
echo "Running core package tests..."
if [ -d "tests/core" ]; then
    cd tests/core && go test -v ./... && cd ../..
else
    echo "Running core tests from root..."
    go test -v ./tests/core/...
fi

echo ""
echo "Running runtime tests..."
if [ -d "tests/runtime" ]; then
    cd tests/runtime && go test -v ./... && cd ../..
else
    echo "Running runtime tests from root..."
    go test -v ./tests/runtime/...
fi

echo ""
echo "Running crypto tests..."
if [ -d "tests/crypto" ]; then
    cd tests/crypto && go test -v ./... && cd ../..
else
    echo "Running crypto tests from root..."
    go test -v ./tests/crypto/...
fi

echo ""
echo "All tests completed successfully!" 

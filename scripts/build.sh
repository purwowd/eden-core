#!/bin/bash
# Eden Core Professional Build Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Build configuration
BINARY_NAME="eden"
EDEN_RUN_BINARY="eden-run"
BIN_DIR="bin"
CLI_CMD="./cmd/eden"
EDEN_RUN_CMD="./cmd/eden-run"

# Version information
VERSION=${VERSION:-"dev"}
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build flags
LDFLAGS="-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.gitCommit=${GIT_COMMIT}"

echo -e "${BLUE}🔨 Eden Core Professional Build${NC}"
echo -e "${BLUE}================================${NC}"
echo ""
echo -e "Version: ${GREEN}${VERSION}${NC}"
echo -e "Build Time: ${GREEN}${BUILD_TIME}${NC}"
echo -e "Git Commit: ${GREEN}${GIT_COMMIT}${NC}"
echo ""

# Clean previous builds
echo -e "${YELLOW}🧹 Cleaning previous builds...${NC}"
rm -rf ${BIN_DIR}/
mkdir -p ${BIN_DIR}

# Build CLI binary
echo -e "${YELLOW}🔨 Building CLI binary...${NC}"
go build -ldflags="${LDFLAGS}" -o ${BIN_DIR}/${BINARY_NAME} ${CLI_CMD}
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[SUCCESS] CLI binary built successfully${NC}"
else
    echo -e "${RED}[ERROR] CLI binary build failed${NC}"
    exit 1
fi

# Build Eden-run binary
echo -e "${YELLOW}[PERFORMANCE] Building Eden-run binary...${NC}"
go build -ldflags="${LDFLAGS}" -o ${BIN_DIR}/${EDEN_RUN_BINARY} ${EDEN_RUN_CMD}
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[SUCCESS] Eden-run binary built successfully${NC}"
else
    echo -e "${RED}[ERROR] Eden-run binary build failed${NC}"
    exit 1
fi

# Show binary information
echo ""
echo -e "${BLUE}[PACKAGE] Build Results:${NC}"
echo -e "CLI Binary: ${GREEN}${BIN_DIR}/${BINARY_NAME}${NC}"
echo -e "Eden-run Binary: ${GREEN}${BIN_DIR}/${EDEN_RUN_BINARY}${NC}"
echo -e "Version: ${GREEN}${VERSION}${NC}"
echo ""

# Show file sizes
if command -v ls >/dev/null 2>&1; then
    echo -e "${BLUE}[STATS] Binary Sizes:${NC}"
    ls -lh ${BIN_DIR}/ | awk '{print $5 " " $9}'
fi

echo ""
echo -e "${GREEN}[COMPLETE] Build completed successfully!${NC}"
echo ""
echo -e "${BLUE}Usage:${NC}"
echo -e "  CLI: ./${BIN_DIR}/${BINARY_NAME} -help"
echo -e "  Runner: ./${BIN_DIR}/${EDEN_RUN_BINARY} <protected_file>" 

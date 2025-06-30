#!/bin/bash

# Eden Core Project Cleanup Script
# This script cleans up temporary files, build artifacts, and test debris

set -e

echo "🧹 Starting Eden Core project cleanup..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Remove compiled binaries
print_status "Cleaning compiled binaries..."
rm -f bin/eden bin/eden-run
if [ -d "bin" ] && [ -z "$(ls -A bin)" ]; then
    print_status "Binary directory is clean"
else
    print_warning "Some files remain in bin/ directory"
fi

# Remove test artifacts
print_status "Cleaning test artifacts..."
rm -rf tests/unit/logs/
rm -rf tests/*/logs/
rm -f coverage.out coverage.html coverage.xml
rm -f *.prof

# Remove database files
print_status "Cleaning database files..."
find . -name "*.db" -type f -delete
find . -name "*.db-shm" -type f -delete
find . -name "*.db-wal" -type f -delete
find . -name "*.sqlite" -type f -delete
find . -name "*.sqlite3" -type f -delete

# Remove temporary files
print_status "Cleaning temporary files..."
find . -name "*.tmp" -type f -delete
find . -name "*~" -type f -delete
find . -name "*.bak" -type f -delete
rm -rf tmp/ temp/

# Remove OS-specific files
print_status "Cleaning OS-specific files..."
find . -name ".DS_Store" -type f -delete
find . -name "Thumbs.db" -type f -delete

# Remove IDE files
print_status "Cleaning IDE files..."
rm -f *.sublime-*
rm -f .vscode/settings.json .vscode/launch.json 2>/dev/null || true

# Remove environment files (but keep examples)
print_status "Cleaning environment files..."
rm -f .env .env.local .env.production
rm -f config.local.*

# Remove backup directories if empty
print_status "Cleaning backup directories..."
if [ -d "backups" ] && [ -z "$(ls -A backups)" ]; then
    print_status "Backups directory is clean"
fi

if [ -d "keys" ] && [ -z "$(ls -A keys)" ]; then
    print_status "Keys directory is clean"
fi

if [ -d "protected" ] && [ -z "$(ls -A protected)" ]; then
    print_status "Protected directory is clean"
fi

# Show cleanup summary
echo ""
echo "📊 Cleanup Summary:"
echo "=================="

# Count files by type
db_files=$(find . -name "*.db*" -type f 2>/dev/null | wc -l | tr -d ' ')
log_files=$(find . -name "*.log" -type f 2>/dev/null | wc -l | tr -d ' ')
tmp_files=$(find . -name "*.tmp" -o -name "*~" -o -name "*.bak" -type f 2>/dev/null | wc -l | tr -d ' ')
bin_files=$(ls bin/ 2>/dev/null | wc -l | tr -d ' ')

print_status "Database files: $db_files"
print_status "Log files: $log_files" 
print_status "Temporary files: $tmp_files"
print_status "Binary files: $bin_files"

# Calculate total space saved
space_saved=$(du -sh . 2>/dev/null | cut -f1)
print_status "Project size: $space_saved"

echo ""
if [ "$db_files" -eq 0 ] && [ "$log_files" -eq 0 ] && [ "$tmp_files" -eq 0 ] && [ "$bin_files" -eq 0 ]; then
    echo -e "${GREEN}✅ Project cleanup completed successfully!${NC}"
    echo -e "${GREEN}🎉 All temporary files have been removed.${NC}"
else
    echo -e "${YELLOW}⚠️  Some files may still need attention.${NC}"
fi

echo ""
echo "💡 To rebuild the project: make build"
echo "💡 To run tests: make test"
echo "💡 To check git status: git status" 

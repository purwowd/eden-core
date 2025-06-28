#!/bin/bash

# Script to remove emojis from Eden Core codebase
# This script replaces emojis with text-based alternatives

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[LAUNCH] Eden Core Emoji Removal Script${NC}"
echo "========================================"

# Function to replace emojis in a file
process_file() {
    local file="$1"
    echo -e "${YELLOW}[PROCESS] Processing $file${NC}"
    
    # Create a backup
    cp "$file" "$file.bak"
    
    # Replace emojis with text alternatives
    # Note: Using a different sed format to handle more complex patterns
    sed -i.tmp '
        s/[[SUCCESS]]/[SUCCESS]/g
        s/[[ERROR]]/[ERROR]/g
        s/[[LAUNCH]]/[LAUNCH]/g
        s/[[SUCCESS]]/[SUCCESS]/g
        s/[[PACKAGE]]/[PACKAGE]/g
        s/[[TAG][TAG]]/[TAG]/g
        s/[[SECURE]]/[SECURE]/g
        s/[[STRONG]]/[STRONG]/g
        s/[[TARGET]]/[TARGET]/g
        s/[[STATS]]/[STATS]/g
        s/[[DOCS]]/[DOCS]/g
        s/[[STAR]]/[STAR]/g
        s/[[FAST]]/[FAST]/g
        s/[[GEM]]/[GEM]/g
        s/[[SECURITY]]/[SECURITY]/g
        s/[[KEY]]/[KEY]/g
        s/[[SUCCESS]]/[SUCCESS]/g
        s/[[ERROR]]/[ERROR]/g
        s/[[INCREASE]]/[INCREASE]/g
        s/[[MEASURE]]/[MEASURE]/g
        s/[[SYSTEM][TAG]]/[SYSTEM]/g
        s/[[INFO][TAG]]/[INFO]/g
        s/[[WARNING][TAG]]/[WARNING]/g
        s/[[PACKAGE]]/[PACKAGE]/g
        s/[[TIME]]/[TIME]/g
        s/[[VALUE]]/[VALUE]/g
        s/[[WRITE]]/[WRITE]/g
        s/[[PYTHON]]/[PYTHON]/g
        s/[[PHP]]/[PHP]/g
        s/[[TERMINAL]]/[TERMINAL]/g
        s/[[CALC]]/[CALC]/g
        s/[[GLOBAL]]/[GLOBAL]/g
        s/[[SPARKLE]]/[SPARKLE]/g
        s/[[CONFIG]]/[CONFIG]/g
        s/[[SHIELD][TAG]]/[SHIELD]/g
        s/[[SETTINGS][TAG]]/[SETTINGS]/g
        s/[[PROCESS]]/[PROCESS]/g
        s/[[BACKUP]]/[BACKUP]/g
        s/[[ENTERPRISE]]/[ENTERPRISE]/g
        s/[[LINK]]/[LINK]/g
        s/[[CONTROL]]/[CONTROL]/g
        s/[[FILES]]/[FILES]/g
        s/[[TEST]]/[TEST]/g
        s/[[PERFORMANCE]]/[PERFORMANCE]/g
        s/[[LAUNCH]]/[LAUNCH]/g
    ' "$file"
    
    # Remove the temporary file
    rm -f "$file.tmp"
    
    # Check if any changes were made
    if cmp -s "$file" "$file.bak"; then
        echo -e "${BLUE}[INFO] No emojis found in $file${NC}"
        rm "$file.bak"
    else
        echo -e "${GREEN}[SUCCESS] Replaced emojis in $file${NC}"
        rm "$file.bak"
    fi
}

# Find all relevant files
files=$(find . -type f \( -name "*.go" -o -name "*.sh" -o -name "*.py" -o -name "*.php" -o -name "*.yml" -o -name "*.md" -o -name "Makefile" \))

# Process each file
for file in $files; do
    process_file "$file"
done

echo -e "${GREEN}[SUCCESS] Emoji removal complete!${NC}" 

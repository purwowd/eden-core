#!/bin/bash

# Eden Run Installation Script
# This script installs eden-run globally for seamless execution of protected .eden files

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/usr/local/bin"
CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$CURRENT_DIR")"
BIN_DIR="$PROJECT_ROOT/bin"

echo -e "${BLUE}=================================${NC}"
echo -e "${BLUE} Eden Run Installation Script${NC}"
echo -e "${BLUE}=================================${NC}"
echo ""

# Check if running as root for system-wide installation
if [[ $EUID -eq 0 ]]; then
    SYSTEM_INSTALL=true
    echo -e "${YELLOW}Running as root - performing system-wide installation${NC}"
else
    SYSTEM_INSTALL=false
    echo -e "${YELLOW}Running as user - will need sudo for system installation${NC}"
fi

echo ""

# Build binaries if they don't exist
echo -e "${BLUE}Step 1: Building Eden binaries...${NC}"
cd "$PROJECT_ROOT"

if [[ ! -f "$BIN_DIR/eden" || ! -f "$BIN_DIR/eden-run" ]]; then
    echo "Building eden and eden-run..."
    go build -o bin/eden ./cmd/eden/
    go build -o bin/eden-run ./cmd/eden-run/
    echo -e "${GREEN}[SUCCESS] Binaries built successfully${NC}"
else
    echo -e "${GREEN}[SUCCESS] Binaries already exist${NC}"
fi

echo ""

# Install system-wide
echo -e "${BLUE}Step 2: Installing system-wide...${NC}"

if $SYSTEM_INSTALL; then
    # Running as root
    cp "$BIN_DIR/eden" "$INSTALL_DIR/"
    cp "$BIN_DIR/eden-run" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/eden"
    chmod +x "$INSTALL_DIR/eden-run"
else
    # Need sudo
    echo "Installing eden and eden-run to $INSTALL_DIR (requires sudo)..."
    sudo cp "$BIN_DIR/eden" "$INSTALL_DIR/"
    sudo cp "$BIN_DIR/eden-run" "$INSTALL_DIR/"
    sudo chmod +x "$INSTALL_DIR/eden"
    sudo chmod +x "$INSTALL_DIR/eden-run"
fi

echo -e "${GREEN}[SUCCESS] Binaries installed to $INSTALL_DIR${NC}"
echo ""

# Create useful aliases
echo -e "${BLUE}Step 3: Setting up aliases and functions...${NC}"

ALIAS_FILE="$HOME/.eden_aliases"
cat > "$ALIAS_FILE" << 'EOF'
# Eden Core Aliases and Functions
# Add this to your ~/.bashrc or ~/.zshrc: source ~/.eden_aliases

# Direct execution aliases
alias run-eden='eden-run'
alias eden-exec='eden-run -q'

# Language-specific aliases  
alias python-eden='eden-run -q'
alias php-eden='eden-run -q'
alias js-eden='eden-run -q'
alias node-eden='eden-run -q'

# Protection aliases
alias protect-py='eden -protect -input'
alias protect-php='eden -protect -input'
alias protect-js='eden -protect -input'

# Quick functions
run_protected() {
    if [ $# -eq 0 ]; then
        echo "Usage: run_protected <file.eden>"
        return 1
    fi
    eden-run -q "$1"
}

protect_file() {
    if [ $# -eq 0 ]; then
        echo "Usage: protect_file <source_file> [output_dir]"
        return 1
    fi
    local output_dir="${2:-./protected}"
    eden -protect -input "$1" -output "$output_dir"
}

# Auto-completion for .eden files
if command -v complete &> /dev/null; then
    complete -f -X '!*.eden' eden-run
    complete -f -X '!*.eden' run-eden
fi
EOF

echo -e "${GREEN}[SUCCESS] Aliases created in $ALIAS_FILE${NC}"
echo ""

# File association setup
echo -e "${BLUE}Step 4: Setting up file associations...${NC}"

# Create .eden file handler script
HANDLER_SCRIPT="$INSTALL_DIR/eden-handler"
if $SYSTEM_INSTALL; then
    cat > "$HANDLER_SCRIPT" << 'EOF'
#!/bin/bash
# Eden file handler for double-click execution
exec eden-run -q "$@"
EOF
    chmod +x "$HANDLER_SCRIPT"
else
    sudo tee "$HANDLER_SCRIPT" > /dev/null << 'EOF'
#!/bin/bash
# Eden file handler for double-click execution
exec eden-run -q "$@"
EOF
    sudo chmod +x "$HANDLER_SCRIPT"
fi

echo -e "${GREEN}[SUCCESS] File handler created${NC}"
echo ""

# Create desktop entry (Linux)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo -e "${BLUE}Step 5: Creating Linux desktop entry...${NC}"
    
    DESKTOP_FILE="$HOME/.local/share/applications/eden-run.desktop"
    mkdir -p "$(dirname "$DESKTOP_FILE")"
    
    cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Name=Eden Run
Comment=Execute protected .eden files
Exec=eden-run %f
Icon=application-x-executable
Terminal=true
Type=Application
Categories=Development;
MimeType=application/x-eden;
EOF
    
    # Register MIME type
    MIME_FILE="$HOME/.local/share/mime/packages/eden.xml"
    mkdir -p "$(dirname "$MIME_FILE")"
    
    cat > "$MIME_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-eden">
    <comment>Eden Protected File</comment>
    <glob pattern="*.eden"/>
    <icon name="application-x-executable"/>
  </mime-type>
</mime-info>
EOF
    
    update-mime-database "$HOME/.local/share/mime" 2>/dev/null || true
    echo -e "${GREEN}[SUCCESS] Linux desktop integration configured${NC}"
    
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo -e "${BLUE}Step 5: macOS integration notes...${NC}"
    echo -e "${YELLOW}For macOS file association, you can manually set .eden files to open with Terminal${NC}"
fi

echo ""

# Installation complete
echo -e "${GREEN}=================================${NC}"
echo -e "${GREEN} Installation Complete! ${NC}"
echo -e "${GREEN}=================================${NC}"
echo ""

echo -e "${BLUE}Quick Usage Examples:${NC}"
echo -e "  ${GREEN}eden-run myapp.eden${NC}         # Run with banner"
echo -e "  ${GREEN}eden-run -q myapp.eden${NC}      # Run silently"
echo -e "  ${GREEN}run-eden myapp.eden${NC}         # Using alias"
echo ""

echo -e "${BLUE}To enable aliases, add to your shell profile:${NC}"
echo -e "  ${YELLOW}echo 'source ~/.eden_aliases' >> ~/.bashrc${NC}"
echo -e "  ${YELLOW}echo 'source ~/.eden_aliases' >> ~/.zshrc${NC}"
echo ""

echo -e "${BLUE}Verify installation:${NC}"
echo -e "  ${GREEN}which eden-run${NC}"
echo -e "  ${GREEN}eden-run --help${NC}"
echo ""

echo -e "${GREEN}[COMPLETE] Eden Run is now installed and ready to use!${NC}"
echo -e "${GREEN}Protected .eden files can now be executed like normal files.${NC}" 

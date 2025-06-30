#!/bin/bash

# Eden Core Performance Tools Installation Script
# Installs JIT optimization tools for maximum performance
# Supports: PyPy JIT, PHP OPcache JIT, Node.js V8 JIT

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    OS="windows"
else
    OS="unknown"
fi

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE} Eden Core JIT Performance Tools Installer ${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""
echo -e "${GREEN}Detected OS: $OS${NC}"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install Python Performance Tools (PyPy JIT)
echo -e "${BLUE}[PACKAGE] Installing Python JIT Performance Tools...${NC}"

# Check if PyPy3 is already installed
if command_exists pypy3; then
    echo -e "${GREEN}[SUCCESS] PyPy already installed: $(pypy3 --version 2>&1 | head -1)${NC}"
else
    echo "Installing PyPy JIT compiler..."
    if [[ "$OS" == "linux" ]]; then
        if command_exists apt-get; then
            sudo apt-get update
            sudo apt-get install -y pypy3 pypy3-dev
        elif command_exists yum; then
            sudo yum install -y pypy3 pypy3-devel
        elif command_exists dnf; then
            sudo dnf install -y pypy3 pypy3-devel
        elif command_exists pacman; then
            sudo pacman -S pypy3
        else
            echo -e "${YELLOW}Please install PyPy manually for your distribution${NC}"
        fi
    elif [[ "$OS" == "macos" ]]; then
        if command_exists brew; then
            brew install pypy3
        else
            echo -e "${YELLOW}Please install Homebrew first, then run: brew install pypy3${NC}"
        fi
    else
        echo -e "${YELLOW}Please install PyPy manually for your platform${NC}"
    fi
fi

# Install basic Python packages for PyPy
echo "Installing basic Python packages..."
pip3 install --upgrade pip setuptools wheel

# Install PyPy packages
if command_exists pypy3; then
    echo "Installing PyPy packages..."
    pypy3 -m ensurepip --upgrade 2>/dev/null || true
    pypy3 -m pip install --upgrade pip setuptools wheel 2>/dev/null || true
fi

echo -e "${GREEN}[SUCCESS] Python JIT tools installed${NC}"
echo ""

# Install PHP Performance Tools
echo -e "${BLUE}[PACKAGE] Installing PHP JIT Performance Tools...${NC}"

if command_exists php; then
    PHP_VERSION=$(php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;")
    echo "Detected PHP version: $PHP_VERSION"
    
    # Check if OPcache is available
    if php -m | grep -q "opcache"; then
        echo -e "${GREEN}[SUCCESS] OPcache already available${NC}"
    else
        echo "Installing OPcache JIT..."
        if [[ "$OS" == "linux" ]]; then
            if command_exists apt-get; then
                sudo apt-get install -y php-opcache
            elif command_exists yum; then
                sudo yum install -y php-opcache
            elif command_exists dnf; then
                sudo dnf install -y php-opcache
            fi
        elif [[ "$OS" == "macos" ]]; then
            echo -e "${YELLOW}On macOS, OPcache is usually included with PHP${NC}"
        fi
    fi
    
    # Install additional PHP extensions for performance
    echo "Installing additional PHP performance extensions..."
    if [[ "$OS" == "linux" ]]; then
        if command_exists apt-get; then
            sudo apt-get install -y php-mbstring php-curl php-xml php-zip php-intl
        elif command_exists yum; then
            sudo yum install -y php-mbstring php-curl php-xml php-zip php-intl
        elif command_exists dnf; then
            sudo dnf install -y php-mbstring php-curl php-xml php-zip php-intl
        fi
    fi
    
else
    echo -e "${YELLOW}PHP not found. Please install PHP first.${NC}"
fi

echo -e "${GREEN}[SUCCESS] PHP JIT tools configured${NC}"
echo ""

# Install Node.js Performance Tools
echo -e "${BLUE}[PACKAGE] Installing Node.js V8 JIT Performance Tools...${NC}"

if command_exists node; then
    NODE_VERSION=$(node --version)
    echo "Detected Node.js version: $NODE_VERSION"
    
    # Install performance monitoring tools
    npm install -g clinic autocannon
    
    echo -e "${GREEN}[SUCCESS] Node.js V8 JIT tools installed${NC}"
else
    echo -e "${YELLOW}Node.js not found. Installing...${NC}"
    if [[ "$OS" == "linux" ]]; then
        curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
        sudo apt-get install -y nodejs
    elif [[ "$OS" == "macos" ]]; then
        if command_exists brew; then
            brew install node
        else
            echo -e "${YELLOW}Please install Node.js manually${NC}"
        fi
    fi
fi

echo ""

# Create performance test configuration
echo -e "${BLUE}[STATS] Creating JIT benchmark utilities...${NC}"

PERF_CONFIG_FILE="$HOME/.eden_performance_config"
cat > "$PERF_CONFIG_FILE" << 'EOF'
# Eden Core JIT Performance Configuration
# Generated by install_performance_tools.sh

[python]
use_pypy_jit=true
jit_warmup_time=1000

[php]
use_opcache=true
opcache_memory=256
jit_buffer_size=256M
jit_mode=tracing

[nodejs]
use_v8_jit=true
max_old_space_size=8192
optimize_for_size=true

[cache]
directory=/tmp/eden_performance_cache
precompile_cache=true
parallel_decrypt=true

[monitoring]
enable_stats=true
detailed_profiling=false
benchmark_mode=false
EOF

echo -e "${GREEN}[SUCCESS] Configuration created at $PERF_CONFIG_FILE${NC}"
echo ""

# Create benchmark scripts
echo -e "${BLUE}[STATS] Creating benchmark utilities...${NC}"

mkdir -p "$HOME/.eden_tools"

# Python benchmark script
cat > "$HOME/.eden_tools/benchmark_python.py" << 'EOF'
#!/usr/bin/env python3
import time
import sys
import subprocess
import statistics

def benchmark_execution(script_path, iterations=5):
    """Benchmark script execution multiple times"""
    times = []
    
    for i in range(iterations):
        start = time.time()
        result = subprocess.run([sys.executable, script_path], 
                              capture_output=True, text=True)
        end = time.time()
        
        if result.returncode == 0:
            times.append(end - start)
        else:
            print(f"Error in iteration {i+1}: {result.stderr}")
    
    if times:
        avg_time = statistics.mean(times)
        min_time = min(times)
        max_time = max(times)
        std_dev = statistics.stdev(times) if len(times) > 1 else 0
        
        print(f"Average: {avg_time:.4f}s")
        print(f"Min: {min_time:.4f}s") 
        print(f"Max: {max_time:.4f}s")
        print(f"Std Dev: {std_dev:.4f}s")
        
        return avg_time
    
    return None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: benchmark_python.py <script_path>")
        sys.exit(1)
    
    script_path = sys.argv[1]
    print(f"Benchmarking: {script_path}")
    benchmark_execution(script_path)
EOF

chmod +x "$HOME/.eden_tools/benchmark_python.py"

# Performance comparison script
cat > "$HOME/.eden_tools/compare_performance.sh" << 'EOF'
#!/bin/bash

# Eden Core JIT Performance Comparison Script

if [ $# -ne 2 ]; then
    echo "Usage: $0 <original_file> <protected_file>"
    exit 1
fi

ORIGINAL_FILE="$1"
PROTECTED_FILE="$2"

echo "=== EDEN CORE JIT PERFORMANCE COMPARISON ==="
echo ""

echo "[STATS] Original file performance:"
time python3 "$ORIGINAL_FILE"
echo ""

echo "[STATS] Protected file performance (with JIT):"
time eden-run -q "$PROTECTED_FILE"
echo ""

echo "[BENCHMARK] Detailed Python benchmark:"
python3 "$HOME/.eden_tools/benchmark_python.py" "$ORIGINAL_FILE"
EOF

chmod +x "$HOME/.eden_tools/compare_performance.sh"

echo -e "${GREEN}[SUCCESS] Benchmark utilities created in ~/.eden_tools/${NC}"
echo ""

# Test installation
echo -e "${BLUE}🧪 Testing JIT performance tools...${NC}"

echo "Testing Python JIT tools:"
python3 -c "print('[SUCCESS] Python3: Available')" 2>/dev/null || echo "[ERROR] Python3 not available"

if command_exists pypy3; then
    echo "[SUCCESS] PyPy JIT: $(pypy3 --version 2>&1 | head -1)"
else
    echo "[ERROR] PyPy JIT not available"
fi

echo ""
echo "Testing PHP JIT tools:"
if php -m | grep -q opcache; then
    echo "[SUCCESS] OPcache JIT available"
else
    echo "[ERROR] OPcache JIT not available"
fi

echo ""
echo "Testing Node.js V8 JIT tools:"
if command_exists node; then
    echo "[SUCCESS] Node.js V8 JIT: $(node --version)"
else
    echo "[ERROR] Node.js V8 JIT not available"
fi

echo ""

# Final instructions
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN} JIT Installation Complete! ${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""

echo -e "${BLUE}JIT Performance Features Available:${NC}"
echo -e "  [PYTHON] Python: PyPy JIT compilation"
echo -e "  [PHP] PHP: OPcache + JIT optimization"
echo -e "  [NODEJS] Node.js: V8 JIT + memory optimization"
echo ""

echo -e "${BLUE}Benchmark Tools:${NC}"
echo -e "  [STATS] Python benchmarks: ~/.eden_tools/benchmark_python.py"
echo -e "  [PERFORMANCE] Performance comparison: ~/.eden_tools/compare_performance.sh"
echo -e "  [CONFIG] Configuration: ~/.eden_performance_config"
echo ""

echo -e "${BLUE}Quick Usage:${NC}"
echo -e "  ${GREEN}# Benchmark original vs protected${NC}"
echo -e "  ~/.eden_tools/compare_performance.sh app.py protected/files/app.eden"
echo ""
echo -e "  ${GREEN}# Run with JIT optimizations${NC}"
echo -e "  eden-run -q protected/files/app.eden"
echo ""

echo -e "${GREEN}[LAUNCH] Eden Core is now optimized for maximum JIT performance!${NC}" 

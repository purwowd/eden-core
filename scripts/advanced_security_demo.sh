#!/bin/bash

# Eden Core Advanced Security Features Demo Script
# This script demonstrates all the new advanced security features

set -e

echo "[LAUNCH] EDEN CORE ADVANCED SECURITY FEATURES COMPREHENSIVE DEMO"
echo "=================================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create demo applications
echo -e "${BLUE}[WRITE] Creating demo applications...${NC}"

# Create a critical business app
cat > critical_business_app.py << 'EOF'
#!/usr/bin/env python3
"""
Critical Business Application
Requires multiple approvals for access (MultiAuth)
"""
import os
import sys

class CriticalBusinessLogic:
    def __init__(self):
        self.secret_algorithm = "Proprietary trading algorithm"
        self.customer_data = ["customer1", "customer2", "customer3"]
    
    def execute_trade(self, amount):
        print(f"[SECURITY] Executing critical trade: ${amount}")
        return f"Trade executed with proprietary algorithm"
    
    def get_customer_data(self):
        print("[SECURE] Accessing sensitive customer data")
        return self.customer_data

if __name__ == "__main__":
    print("[LAUNCH] Critical Business Application")
    print("Protected with MultiAuth (2-of-3)")
    
    app = CriticalBusinessLogic()
    result = app.execute_trade(100000)
    customers = app.get_customer_data()
    
    print(f"Result: {result}")
    print(f"Customers: {len(customers)} records")
EOF

# Create a time-sensitive app
cat > time_sensitive_app.py << 'EOF'
#!/usr/bin/env python3
"""
Time-Sensitive Application
Locked until specific date/time (TimeLock)
"""
import datetime

class ProductLauncher:
    def __init__(self):
        self.launch_date = "2024-12-25"
        self.secret_features = ["AI Integration", "Advanced Analytics", "Quantum Computing"]
    
    def reveal_features(self):
        print("[LAUNCH] New Product Features:")
        for i, feature in enumerate(self.secret_features, 1):
            print(f"   {i}. {feature}")
    
    def launch_product(self):
        print("[LAUNCH] Launching new product!")
        print("Revolutionary features now available!")

if __name__ == "__main__":
    print("[LAUNCH] Time-Sensitive Product Launch App")
    print("Locked until Christmas 2024")
    
    launcher = ProductLauncher()
    launcher.reveal_features()
    launcher.launch_product()
EOF

# Create a valuable intellectual property
cat > valuable_ip.py << 'EOF'
#!/usr/bin/env python3
"""
Valuable Intellectual Property
Ownership tracked via ownership control system
"""

class ProprietaryAlgorithm:
    def __init__(self):
        self.secret_formula = "E = mc²" # Simplified for demo
        self.patent_value = 1000000
    
    def calculate_efficiency(self, input_data):
        # Secret proprietary calculation
        efficiency = sum(input_data) * 0.618  # Golden ratio
        return efficiency * 1.414  # Square root of 2
    
    def get_patent_info(self):
        return {
            "formula": self.secret_formula,
            "estimated_value": self.patent_value,
            "owner": "Eden Core Holdings"
        }

if __name__ == "__main__":
    print("[STATS] Valuable Intellectual Property")
    print("Protected with ownership control system")
    
    algo = ProprietaryAlgorithm()
    efficiency = algo.calculate_efficiency([1, 2, 3, 4, 5])
    patent_info = algo.get_patent_info()
    
    print(f"Efficiency calculated: {efficiency:.2f}")
    print(f"Patent value: ${patent_info['estimated_value']:,}")
EOF

# Create an enterprise team app
cat > enterprise_team_app.py << 'EOF'
#!/usr/bin/env python3
"""
Enterprise Team Application
Access controlled by PolicyScript system with team and reputation requirements
"""

class EnterpriseSystem:
    def __init__(self):
        self.authorized_teams = ["developers", "security", "management"]
        self.min_reputation = 75
        self.sensitive_data = "Company financial projections Q4 2024"
    
    def process_payroll(self):
        print("[PROCESS] Processing company payroll")
        return "Payroll processed for 1000 employees"
    
    def access_financial_data(self):
        print("[STATS] Accessing financial projections")
        return self.sensitive_data
    
    def backup_system(self):
        print("[BACKUP] Creating enterprise backup")
        return "System backup completed"

if __name__ == "__main__":
    print("[ENTERPRISE] Enterprise Team Application")
    print("Requires: Team membership + 75+ reputation + Business hours")
    
    system = EnterpriseSystem()
    result1 = system.process_payroll()
    result2 = system.access_financial_data()
    result3 = system.backup_system()
    
    print(f"[SUCCESS] {result1}")
    print(f"[SUCCESS] Data: {result2}")
    print(f"[SUCCESS] {result3}")
EOF

echo -e "${GREEN}[SUCCESS] Demo applications created${NC}"
echo ""

# Demo 1: MultiAuth Protection
echo -e "${YELLOW}[SECURITY] DEMO 1: MULTIAUTH PROTECTION${NC}"
echo "========================================"
echo "Protecting critical business app with 2-of-3 MultiAuth..."
echo ""

./eden -protect -input critical_business_app.py -multiauth '2-of-3' -verbose
echo ""

# Demo 2: TimeLock Protection
echo -e "${YELLOW}[TIME] DEMO 2: TIMELOCK PROTECTION${NC}"
echo "========================================"
echo "Protecting time-sensitive app with Christmas 2024 lock..."
echo ""

./eden -protect -input time_sensitive_app.py -timelock '2024-12-25T00:00:00Z' -verbose
echo ""

# Demo 3: Ownership Control
echo -e "${YELLOW}[VALUE] DEMO 3: OWNERSHIP CONTROL${NC}"
echo "========================================"
echo "Protecting valuable IP with ownership control (1M value)..."
echo ""

./eden -protect -input valuable_ip.py -ownership-mode -ownership-value 1000000 -verbose
echo ""

# Demo 4: PolicyScript System
echo -e "${YELLOW}[POLICY] DEMO 4: POLICYSCRIPT SYSTEM${NC}"
echo "========================================"
echo "Protecting enterprise app with complex PolicyScript policy..."
echo ""

./eden -protect -input enterprise_team_app.py -policyscript 'developers OP_CHECKTEAM 75 OP_CHECKREP OP_AND business_hours OP_CHECKTIME OP_AND' -verbose
echo ""

# Demo 5: Combined Features
echo -e "${YELLOW}[CONTROL] DEMO 5: COMBINED FEATURES${NC}"
echo "========================================"
echo "Ultimate protection: MultiAuth + TimeLock + Ownership + PolicyScript..."
echo ""

./eden -protect -input enterprise_team_app.py -multiauth '3-of-5' -timelock '2024-06-01T00:00:00Z' -ownership-mode -policy-type 'enterprise' -verbose
echo ""

# Demo 6: Sample Projects Protection
echo -e "${YELLOW}[LAUNCH] DEMO 6: SAMPLE PROJECTS${NC}"
echo "========================================"
echo "Protecting real-world applications from sample-projects..."
echo ""

echo "Protecting Django app with enterprise features..."
./eden -protect -input sample-projects/django-app/app.py -multiauth '2-of-3' -timelock '+7days' -verbose

echo ""
echo "Protecting FastAPI app with ownership control..."
./eden -protect -input sample-projects/fastapi-app/app.py -ownership-mode -ownership-value 500000 -verbose

echo ""
echo "Protecting Laravel app with PolicyScript policy..."
./eden -protect -input sample-projects/laravel-app/app.php -policy-type 'enterprise' -verbose

echo ""

# Show results
echo -e "${GREEN}[FILES] PROTECTION RESULTS${NC}"
echo "========================================"
echo "Protected files created:"
ls -la protected/ 2>/dev/null || echo "No protected directory found"

echo ""
echo "Keys created:"
ls -la *.key 2>/dev/null || echo "No key files found"

echo ""

# Performance benchmark
echo -e "${BLUE}[PERFORMANCE] PERFORMANCE BENCHMARK${NC}"
echo "========================================"
./eden -benchmark

echo ""

# Full demo
echo -e "${BLUE}[LAUNCH] FULL ADVANCED FEATURES DEMO${NC}"
echo "========================================"
./eden -demo

echo ""
echo -e "${GREEN}[COMPLETE] ALL ADVANCED SECURITY FEATURES DEMOS COMPLETED SUCCESSFULLY!${NC}"
echo ""
echo -e "${BLUE}[INFO] Next Steps:${NC}"
echo "1. Run './eden -examples' for detailed usage examples"
echo "2. Try './eden -multiauth-status -input critical_business_app.py.multiauth'"
echo "3. Test './eden -timelock-status -input time_sensitive_app.py.timelock'"
echo "4. Explore './eden -ownership-verify -input valuable_ip.py.ownership'"
echo ""
echo -e "${YELLOW}[LAUNCH] Eden Core is ready for production with advanced security!${NC}"

# Cleanup demo files
echo ""
echo -e "${BLUE}🧹 Cleaning up demo files...${NC}"
rm -f critical_business_app.py time_sensitive_app.py valuable_ip.py enterprise_team_app.py sample_app.py

echo -e "${GREEN}[SUCCESS] Demo script completed!${NC}" 

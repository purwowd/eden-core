# Eden Core Makefile
# Enterprise-Grade Go Project Build System with Mocking Support

.PHONY: build clean test install lint fmt vet help run-cli run-web dev generate-mocks test-unit test-integration benchmark

# Build variables
BINARY_NAME=eden
EDEN_RUN_BINARY=eden-run
BIN_DIR=bin
CLI_CMD=./cmd/eden
EDEN_RUN_CMD=./cmd/eden-run

# Version and build info
VERSION=$(shell git describe --tags --always --dirty)
BUILD_DATE=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT=$(shell git rev-parse --short HEAD)
LDFLAGS=-ldflags="-s -w -X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE) -X main.gitCommit=$(GIT_COMMIT)"

# Go build and test flags
GO_BUILD_FLAGS=$(LDFLAGS)
GO_TEST_FLAGS=-race -coverprofile=coverage.out -covermode=atomic
GO_BENCH_FLAGS=-benchmem -cpuprofile=cpu.prof -memprofile=mem.prof

# Coverage thresholds
COVERAGE_THRESHOLD=80

## help: Show this help message
help:
	@echo 'Usage:'
	@echo '  make <target>'
	@echo ''
	@echo 'Build Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST) | grep -E '^  .*build|install|cross'
	@echo ''
	@echo 'Development Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST) | grep -E '^  .*test|coverage|mock|clean'
	@echo ''
	@echo 'Runtime Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST) | grep -E '^  .*run|protect|benchmark'
	@echo ''
	@echo 'Analysis Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST) | grep -E '^  .*security|lint|vet'

## build: Build CLI and eden-run binaries
build: clean
	@echo "[BUILD] Building Eden Core CLI and Runner..."
	@mkdir -p $(BIN_DIR)
	@go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME) $(CLI_CMD)
	@go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(EDEN_RUN_BINARY) $(EDEN_RUN_CMD)
	@echo "[SUCCESS] Build complete!"
	@echo "   [PACKAGE] Eden CLI: $(BIN_DIR)/$(BINARY_NAME)"
	@echo "   [PACKAGE] Eden Run: $(BIN_DIR)/$(EDEN_RUN_BINARY)"
	@echo "   [SIZE] Total Size: $$(du -ch $(BIN_DIR)/* | tail -1 | cut -f1)"
	@echo "   [VERSION] Version: $(VERSION)"

## build-all: Cross-compile for all platforms
build-all: clean
	@echo "[GLOBAL] Cross-compiling for all platforms..."
	@mkdir -p $(BIN_DIR)
	@echo "  Building for Linux AMD64..."
	@GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-linux-amd64 $(CLI_CMD)
	@echo "  Building for Linux ARM64..."
	@GOOS=linux GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-linux-arm64 $(CLI_CMD)
	@echo "  Building for Windows AMD64..."
	@GOOS=windows GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CLI_CMD)
	@echo "  Building for macOS AMD64..."
	@GOOS=darwin GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-darwin-amd64 $(CLI_CMD)
	@echo "  Building for macOS ARM64..."
	@GOOS=darwin GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-darwin-arm64 $(CLI_CMD)
	@echo "[SUCCESS] Cross-compilation complete!"
	@ls -la $(BIN_DIR)/

## clean: Clean build artifacts and caches
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)/
	@go clean -cache -testcache -modcache
	@echo "Clean complete!"

## cleanup: Clean up project - remove temporary files, databases, and test artifacts
cleanup:
	@echo "🧹 Cleaning up project..."
	@chmod +x scripts/cleanup.sh
	@./scripts/cleanup.sh

## generate-mocks: Generate mock implementations
generate-mocks:
	@echo "[TOOLS] Generating mock implementations..."
	@go install github.com/golang/mock/mockgen@latest
	@go generate ./tests/mocks/...
	@echo "[SUCCESS] Mock generation complete!"

## test: Run all tests with coverage
test: generate-mocks
	@echo "[TESTING] Running comprehensive test suite..."
	@go test $(GO_TEST_FLAGS) ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "[SUCCESS] Tests complete!"
	@echo "   [STATS] Coverage report: coverage.html"
	@echo "   [STATS] Coverage: $$(go tool cover -func=coverage.out | grep total | awk '{print $$3}')"

## test-unit: Run unit tests with mocks
test-unit: generate-mocks
	@echo "[TEST] Running unit tests with mocks..."
	@go test $(GO_TEST_FLAGS) ./tests/unit/... ./tests/mocks/...
	@echo "[SUCCESS] Unit tests complete!"

## test-integration: Run integration tests
test-integration: build
	@echo "[TEST] Running integration tests..."
	@go test $(GO_TEST_FLAGS) ./tests/integration_test.go
	@echo "[SUCCESS] Integration tests complete!"

## test-coverage: Generate detailed coverage report
test-coverage: test
	@echo "[STATS] Generating detailed coverage analysis..."
	@go tool cover -func=coverage.out > coverage.txt
	@echo "Coverage by package:"
	@grep -v "total:" coverage.txt
	@echo ""
	@echo "Overall coverage: $$(grep "total:" coverage.txt | awk '{print $$3}')"
	@if [ $$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//') -lt $(COVERAGE_THRESHOLD) ]; then \
		echo "[ERROR] Coverage below threshold ($(COVERAGE_THRESHOLD)%)"; \
		exit 1; \
	else \
		echo "[SUCCESS] Coverage meets threshold ($(COVERAGE_THRESHOLD)%)"; \
	fi

## install: Install binaries to GOPATH/bin
install:
	@echo "Installing Eden Core..."
	@go install $(CLI_CMD)
	@go install $(EDEN_RUN_CMD)
	@echo "Installation complete!"

## install-runner: Install eden-run system-wide with setup
install-runner: build
	@echo "Installing Eden Run system-wide..."
	@chmod +x scripts/install_eden_runner.sh
	@./scripts/install_eden_runner.sh

## lint: Run linters (requires golangci-lint)
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "WARNING: golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

## fmt: Format Go code
fmt:
	@echo "Formatting Go code..."
	@go fmt ./...
	@echo "Formatting complete!"

## vet: Run go vet
vet:
	@echo "Running go vet..."
	@go vet ./...
	@echo "Vet complete!"

## run-cli: Run CLI application
run-cli: build
	@echo "Running Eden CLI..."
	@./$(BIN_DIR)/$(BINARY_NAME) -help

## dev: Start development environment
dev: fmt vet test
	@echo "Starting development environment..."
	@echo "Development environment ready!"

# Security targets
## protect-samples: Protect sample projects
protect-samples: build
	@echo "Protecting sample projects..."
	@./$(BIN_DIR)/$(BINARY_NAME) -protect -input sample-projects/laravel-app -recursive
	@./$(BIN_DIR)/$(BINARY_NAME) -protect -input sample-projects/django-app -recursive
	@./$(BIN_DIR)/$(BINARY_NAME) -protect -input sample-projects/fastapi-app -recursive
	@echo "Sample protection complete!"

## benchmark: Run comprehensive performance benchmarks
benchmark: build
	@echo "[LAUNCH] Running comprehensive performance benchmarks..."
	@go test -bench=. -benchmem ./pkg/core/... ./pkg/crypto/... ./tests/unit/... > benchmark.txt
	@echo "[SUCCESS] Go benchmarks complete!"
	@echo ""
	@echo "[PERFORMANCE] Running custom benchmark suite..."
	@go run cmd/eden/benchmarks.go >> benchmark.txt
	@echo "[SUCCESS] Custom benchmarks complete!"
	@echo "[STATS] Benchmark results saved to: benchmark.txt"

## profile: Run performance profiling
profile: build
	@echo "[STATS] Running performance profiling..."
	@go test -cpuprofile=cpu.prof -memprofile=mem.prof -bench=. ./pkg/core/...
	@echo "[SUCCESS] Profiling complete!"
	@echo "   [INSPECT] CPU Profile: cpu.prof"
	@echo "   [MEMORY] Memory Profile: mem.prof"
	@echo "   [STATS] View with: go tool pprof cpu.prof"

## security-scan: Run security analysis
security-scan:
	@echo "[SECURITY] Running security analysis..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "Installing gosec..."; \
		go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; \
		gosec ./...; \
	fi
	@echo "[SUCCESS] Security scan complete!"

## deps-check: Check dependency vulnerabilities
deps-check:
	@echo "[INSPECT] Checking dependencies for vulnerabilities..."
	@go list -json -deps ./... | nancy sleuth
	@echo "[SUCCESS] Dependency check complete!"

## demo: Run advanced security demonstration
demo: build
	@echo "[LAUNCH] Running advanced security demonstration..."
	@./scripts/advanced_security_demo.sh
	@echo "[SUCCESS] Demo complete!"

# Docker targets
## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image..."
	@docker build -t eden-core:latest .
	@echo "Docker build complete!"

## docker-run: Run Docker container
docker-run: docker-build
	@echo "Running Docker container..."
	@docker run -p 8080:8080 eden-core:latest

# Development quality checks
## check: Run all quality checks
check: fmt vet lint test-coverage security-scan
	@echo "[SUCCESS] All quality checks passed!"
	@echo "[SUCCESS] Code is production-ready!"

## ci: Continuous Integration pipeline
ci: generate-mocks check test-integration benchmark
	@echo "[SUCCESS] CI pipeline completed successfully!"

## precommit: Pre-commit quality checks
precommit: fmt vet lint test-unit
	@echo "[SUCCESS] Pre-commit checks passed!"

# Quick development cycle  
## quick: Quick build and test
quick: fmt vet test-unit build
	@echo "[SUCCESS] Quick development cycle complete!"

## dev-setup: Setup development environment
dev-setup:
	@echo "[CONFIG] Setting up development environment..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/golang/mock/mockgen@latest
	@go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	@go mod download
	@echo "[SUCCESS] Development environment ready!"

## release: Create a release build with optimizations
release: clean
	@echo "[LAUNCH] Creating release build..."
	@mkdir -p $(BIN_DIR)
	@CGO_ENABLED=0 go build -a -installsuffix cgo $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME) $(CLI_CMD)
	@echo "[SUCCESS] Release build complete!"
	@echo "   [PACKAGE] Binary: $(BIN_DIR)/$(BINARY_NAME)"
	@echo "   [MEASURE] Size: $$(du -h $(BIN_DIR)/$(BINARY_NAME) | cut -f1)"
	@upx --best $(BIN_DIR)/$(BINARY_NAME) 2>/dev/null || echo "   💡 Install UPX for smaller binaries"

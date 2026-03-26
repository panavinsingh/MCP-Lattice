# MCP-Lattice - MCP Server Security Scanner
# https://github.com/panavinsingh/MCP-Lattice

BINARY_NAME := mcp-lattice
BUILD_DIR := ./bin
MODULE := github.com/panavinsingh/MCP-Lattice

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

# Build flags
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

# Go parameters
GOFLAGS := -trimpath
GOTESTFLAGS := -race -cover -count=1

.PHONY: all build test lint clean install docker-build templates-validate help

## all: Build the binary (default target)
all: build

## build: Compile the binary with version info
build:
	@echo "==> Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/mcp-lattice
	@echo "==> Binary available at $(BUILD_DIR)/$(BINARY_NAME)"

## test: Run all tests with race detector and coverage
test:
	@echo "==> Running tests..."
	go test ./... $(GOTESTFLAGS)

## test-verbose: Run all tests with verbose output
test-verbose:
	@echo "==> Running tests (verbose)..."
	go test ./... $(GOTESTFLAGS) -v

## test-coverage: Run tests and generate coverage report
test-coverage:
	@echo "==> Generating coverage report..."
	@mkdir -p $(BUILD_DIR)
	go test ./... $(GOTESTFLAGS) -coverprofile=$(BUILD_DIR)/coverage.out
	go tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "==> Coverage report at $(BUILD_DIR)/coverage.html"

## lint: Run static analysis
lint:
	@echo "==> Running linter..."
	go vet ./...
	@echo "==> Lint passed"

## clean: Remove build artifacts
clean:
	@echo "==> Cleaning..."
	rm -rf $(BUILD_DIR)/
	@echo "==> Clean complete"

## install: Install the binary to GOPATH/bin
install:
	@echo "==> Installing $(BINARY_NAME)..."
	go install $(GOFLAGS) -ldflags '$(LDFLAGS)' ./cmd/mcp-lattice
	@echo "==> Installed $(BINARY_NAME) to $(shell go env GOPATH)/bin"

## docker-build: Build Docker image
docker-build:
	@echo "==> Building Docker image..."
	docker build -t mcp-lattice/mcp-lattice:$(VERSION) -t mcp-lattice/mcp-lattice:latest .
	@echo "==> Docker image built: mcp-lattice/mcp-lattice:$(VERSION)"

## templates-validate: Validate all security check templates
templates-validate:
	@echo "==> Validating templates..."
	go run ./cmd/mcp-lattice validate-templates
	@echo "==> All templates valid"

## fmt: Format Go source files
fmt:
	@echo "==> Formatting..."
	gofmt -s -w .

## tidy: Tidy Go modules
tidy:
	@echo "==> Tidying modules..."
	go mod tidy

## help: Show this help message
help:
	@echo "MCP-Lattice - MCP Server Security Scanner"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /' | sort

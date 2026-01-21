.PHONY: help test test-coverage test-integration test-watch lint vet fmt build build-all \
        clean ci install-tools docker-test docker-ci docker-build docker-lint docker-clean \
        example check pre-commit docs docs-serve docs-build

# Project info
MODULE := github.com/radiolabme/hamsign
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

# Build settings
GO ?= go
GOFLAGS := -trimpath
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE)

# Output directories
DIST_DIR := dist
BIN_DIR := bin
DOCS_DIR := docs/site

# Example commands to build
EXAMPLES := loadcert signdata verifycert

# Docker settings
COMPOSE_FILE := .docker/docker-compose.yml

# Cross-compilation targets
# Format: GOOS/GOARCH or GOOS/GOARCH/GOARM for ARM variants
# Note: Pure Go builds are distribution-agnostic (works on Alpine, Debian, etc.)
PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	linux/arm/7 \
	linux/arm/6 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64

# ============================================================================
# Help
# ============================================================================

help: ## Show this help message
	@echo "hamsign - Amateur Radio Digital Signing Library"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Development targets:"
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | grep -v "docker-" | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'
	@echo ""
	@echo "Docker targets:"
	@grep -E '^docker-[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

# ============================================================================
# Development targets (require Go installed)
# ============================================================================

test: ## Run unit tests
	$(GO) test -v -race ./...

test-coverage: ## Run tests with coverage report
	$(GO) test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-integration: ## Run integration tests (requires real certificates)
	$(GO) test -v -race -tags=integration ./...

test-watch: ## Run tests in watch mode (requires entr)
	@command -v entr >/dev/null 2>&1 || { echo "Install entr: brew install entr"; exit 1; }
	@echo "Watching for changes... (Ctrl+C to stop)"
	@find . -name '*.go' | entr -c $(GO) test -v ./...

lint: ## Run linter
	@command -v golangci-lint >/dev/null 2>&1 || { echo "Install: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; exit 1; }
	golangci-lint run ./...

vet: ## Run go vet
	$(GO) vet ./...

fmt: ## Format code
	$(GO) fmt ./...
	@echo "Code formatted"

check: fmt vet lint ## Run all checks (fmt, vet, lint)

ci: check test ## Run full CI pipeline (check + test)
	@echo "CI passed ✓"

# ============================================================================
# Build targets
# ============================================================================

build: ## Build example binaries for current platform
	@mkdir -p $(BIN_DIR)
	@for cmd in $(EXAMPLES); do \
		$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$$cmd ./example/$$cmd; \
	done
	@echo "Built: $(EXAMPLES)"

build-all: ## Build examples for all platforms
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		case "$$platform" in \
			*/arm/[67]) \
				GOOS=$$(echo $$platform | cut -d/ -f1); \
				GOARCH=arm; \
				GOARM=$$(echo $$platform | cut -d/ -f3); \
				suffix="$${GOOS}-armv$${GOARM}"; \
				;; \
			*) \
				GOOS=$${platform%/*}; \
				GOARCH=$${platform#*/}; \
				GOARM=""; \
				suffix="$${GOOS}-$${GOARCH}"; \
				;; \
		esac; \
		ext=""; if [ "$$GOOS" = "windows" ]; then ext=".exe"; fi; \
		for cmd in $(EXAMPLES); do \
			output="$(DIST_DIR)/$${cmd}-$${suffix}$${ext}"; \
			echo "Building $$output..."; \
			CGO_ENABLED=0 GOOS=$$GOOS GOARCH=$$GOARCH GOARM=$$GOARM \
				$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $$output ./example/$$cmd || exit 1; \
		done; \
	done
	@echo "All builds complete in $(DIST_DIR)/"

build-darwin: ## Build for macOS (amd64 and arm64) - requires Darwin host
	@if [ "$$(uname -s)" != "Darwin" ]; then echo "Error: macOS builds require Darwin host"; exit 1; fi
	@mkdir -p $(DIST_DIR)
	@for arch in amd64 arm64; do \
		echo "Building darwin/$$arch..."; \
		for cmd in $(EXAMPLES); do \
			CGO_ENABLED=0 GOOS=darwin GOARCH=$$arch \
				$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$$cmd-darwin-$$arch ./example/$$cmd; \
		done; \
	done

build-linux: ## Build for Linux (amd64, arm64, armv7, armv6)
	@mkdir -p $(DIST_DIR)
	@for arch in amd64 arm64; do \
		echo "Building linux/$$arch..."; \
		for cmd in $(EXAMPLES); do \
			CGO_ENABLED=0 GOOS=linux GOARCH=$$arch \
				$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$$cmd-linux-$$arch ./example/$$cmd; \
		done; \
	done
	@for armv in 7 6; do \
		echo "Building linux/armv$$armv (Raspberry Pi)..."; \
		for cmd in $(EXAMPLES); do \
			CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=$$armv \
				$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$$cmd-linux-armv$$armv ./example/$$cmd; \
		done; \
	done

build-windows: ## Build for Windows (amd64 and arm64)
	@mkdir -p $(DIST_DIR)
	@for arch in amd64 arm64; do \
		echo "Building windows/$$arch..."; \
		for cmd in $(EXAMPLES); do \
			CGO_ENABLED=0 GOOS=windows GOARCH=$$arch \
				$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$$cmd-windows-$$arch.exe ./example/$$cmd; \
		done; \
	done

clean: ## Clean build artifacts
	rm -rf $(DIST_DIR) $(BIN_DIR) $(DOCS_DIR) coverage.out coverage.html

# ============================================================================
# Tools
# ============================================================================

install-tools: ## Install development tools
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GO) install golang.org/x/tools/gopls@latest
	$(GO) install github.com/go-delve/delve/cmd/dlv@latest
	$(GO) install golang.org/x/pkgsite/cmd/pkgsite@latest
	@echo "Tools installed"

# ============================================================================
# Documentation
# ============================================================================

PKGSITE := $(shell command -v pkgsite 2>/dev/null || echo "$$($(GO) env GOPATH)/bin/pkgsite")

docs: docs-serve ## Alias for docs-serve

docs-serve: ## Serve API documentation locally (pkg.go.dev style)
	@test -x "$$(command -v pkgsite || echo $$($(GO) env GOPATH)/bin/pkgsite)" || \
		{ echo "Install: go install golang.org/x/pkgsite/cmd/pkgsite@latest"; exit 1; }
	@echo "Starting documentation server at http://localhost:8080/$(MODULE)"
	@echo "Press Ctrl+C to stop"
	@$$(command -v pkgsite || echo $$($(GO) env GOPATH)/bin/pkgsite) -http=localhost:8080 .

docs-build: ## Generate static documentation site
	@test -x "$$(command -v pkgsite || echo $$($(GO) env GOPATH)/bin/pkgsite)" || \
		{ echo "Install: go install golang.org/x/pkgsite/cmd/pkgsite@latest"; exit 1; }
	@mkdir -p $(DOCS_DIR)
	@echo "Generating static documentation..."
	@PKGSITE=$$(command -v pkgsite || echo $$($(GO) env GOPATH)/bin/pkgsite); \
		$$PKGSITE -http=localhost:8081 . & PID=$$!; \
		sleep 3; \
		wget -q -r -np -nH -P $(DOCS_DIR) --cut-dirs=0 \
			-e robots=off \
			"http://localhost:8081/$(MODULE)" \
			"http://localhost:8081/$(MODULE)/hamcert" \
			"http://localhost:8081/$(MODULE)/gabbi" 2>/dev/null || true; \
		kill $$PID 2>/dev/null || true
	@echo "Documentation generated in $(DOCS_DIR)/"

# ============================================================================
# Git hooks
# ============================================================================

install-hooks: ## Install git hooks
	@cp .githooks/pre-commit .git/hooks/pre-commit 2>/dev/null || true
	@cp .githooks/pre-push .git/hooks/pre-push 2>/dev/null || true
	@chmod +x .git/hooks/pre-commit .git/hooks/pre-push 2>/dev/null || true
	@echo "Git hooks installed"

pre-commit: fmt vet ## Run pre-commit checks
	@echo "Pre-commit checks passed ✓"

# ============================================================================
# Docker targets
# ============================================================================

docker-test: ## Run tests in Docker
	@docker compose -f $(COMPOSE_FILE) run --rm test

docker-ci: ## Run full CI in Docker
	@docker compose -f $(COMPOSE_FILE) run --rm ci

docker-build: ## Build all platforms in Docker
	@docker compose -f $(COMPOSE_FILE) run --rm build

docker-lint: ## Run linter in Docker
	@docker compose -f $(COMPOSE_FILE) run --rm lint

docker-clean: ## Clean up Docker resources
	@docker compose -f $(COMPOSE_FILE) down -v --remove-orphans

docker-prune: ## Remove all Docker resources for this project
	@docker compose -f $(COMPOSE_FILE) down -v --remove-orphans --rmi local
	@docker system prune -f --volumes

# ============================================================================
# Example
# ============================================================================

example: build ## Build and show example usage
	@echo ""
	@echo "Example binaries built in $(BIN_DIR)/:"
	@ls -1 $(BIN_DIR)/
	@echo ""
	@echo "Run: ./$(BIN_DIR)/loadcert <tq6-file>"
	@echo "Run: ./$(BIN_DIR)/signdata <p12-file> <password>"
	@echo "Run: ./$(BIN_DIR)/verifycert <tq6-file>"

# ============================================================================
# Release (for maintainers)
# ============================================================================

release-dry-run: ## Test release process without publishing
	@command -v goreleaser >/dev/null 2>&1 || { echo "Install goreleaser"; exit 1; }
	goreleaser release --snapshot --clean

release: ## Create a release (requires GITHUB_TOKEN)
	@command -v goreleaser >/dev/null 2>&1 || { echo "Install goreleaser"; exit 1; }
	goreleaser release --clean


.DEFAULT_GOAL := build

BINARY_NAME := vault-plugin-secrets-oci
BUILD_DIR := bin

VERSION ?= $(shell git describe --tags --always --dirty || echo "v0.0.0-dev")
LDFLAGS := -X main.Version=$(VERSION)

.PHONY: all build clean fmt vet test test-unit test-integration

all: fmt vet build

build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) .

clean:
	@rm -rf $(BUILD_DIR)

fmt:
	go fmt ./...

vet:
	go vet ./...

test: test-unit

test-unit:
	go test -v ./...

test-integration:
	go test -v -tags=integration ./oci-backend -run Integration

# Build for multiple platforms
build-all:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe .

# Enable the plugin in a local Vault dev server
enable:
	vault secrets enable -path=oci vault-plugin-secrets-oci

# Register the plugin with Vault (requires SHA256)
register:
	@echo "Calculate SHA256 and register:"
	@echo "vault write sys/plugins/catalog/secrets/oci sha_256=\\$$(sha256sum bin/$(BINARY_NAME) | cut -d' ' -f1) command=$(BINARY_NAME)"

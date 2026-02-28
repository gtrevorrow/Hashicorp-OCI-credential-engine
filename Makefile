github.com/hashicorp/Hashicorp-OCI-credential-engine

.DEFAULT_GOAL := build

BINARY_NAME := vault-plugin-secrets-oci
BUILD_DIR := bin

.PHONY: all build clean fmt vet test

all: fmt vet build

build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) .

clean:
	@rm -rf $(BUILD_DIR)

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test -v ./...

# Build for multiple platforms
build-all:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe .

# Enable the plugin in a local Vault dev server
enable:
	vault secrets enable -path=oci vault-plugin-secrets-oci

# Register the plugin with Vault (requires SHA256)
register:
	@echo "Calculate SHA256 and register:"
	@echo "vault write sys/plugins/catalog/secrets/oci sha_256=\\$$(sha256sum bin/$(BINARY_NAME) | cut -d' ' -f1) command=$(BINARY_NAME)"

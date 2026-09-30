.PHONY: all build clean test-e2e install fmt vet dev

# Binary names
BINARY=cgmpold
PREFIX=/usr/local

# E2E test configuration
E2E_HOST ?=

# Build targets
all: build

build:
	go build -v -o $(BINARY) .

install: build
	install -m 755 $(BINARY) $(PREFIX)/bin/

clean:
	rm -f $(BINARY)
	go clean

# E2E tests (requires E2E_HOST environment variable)
test-e2e:
	@if [ -z "$(E2E_HOST)" ]; then \
		echo "Error: E2E_HOST must be set to run e2e tests"; \
		echo "Example: make test-e2e E2E_HOST=n4c16-fedora-43-containerd"; \
		exit 1; \
	fi
	cd test/e2e && E2E_HOST=$(E2E_HOST) ./run.sh .

fmt:
	go fmt ./...

vet:
	go vet ./...

# Development
dev: fmt vet build

.DEFAULT_GOAL := build

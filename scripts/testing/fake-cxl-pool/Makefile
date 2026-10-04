# fake-cxl-pool: build the server (host) and the client (host and VMs).
#
#   make            build bin/fake-cxl-pool-server and bin/fake-cxl-pool-client
#   make test       unit tests
#   make lint       go vet and gofmt check

GO      ?= go
PKG     := github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool
BINDIR  := bin
# the client runs in the VMs: build it static
CLIENT_ENV := CGO_ENABLED=0 GOARCH=amd64

all: $(BINDIR)/fake-cxl-pool-server $(BINDIR)/fake-cxl-pool-client

$(BINDIR)/fake-cxl-pool-server: FORCE
	$(GO) build -o $@ $(PKG)/cmd/fake-cxl-pool-server

$(BINDIR)/fake-cxl-pool-client: FORCE
	$(CLIENT_ENV) $(GO) build -o $@ $(PKG)/cmd/fake-cxl-pool-client

test:
	$(GO) test -race $(PKG)/...

lint:
	$(GO) vet $(PKG)/...
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed: $$out"; exit 1; fi

clean:
	rm -rf $(BINDIR)

.PHONY: all test lint clean FORCE
FORCE:

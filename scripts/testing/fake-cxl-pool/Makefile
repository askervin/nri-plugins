# fake-cxl-pool: build the server (host), the client (host and VMs) and the
# DRA pool controller (VMs or a cluster).
#
#   make            build bin/fake-cxl-pool-server, bin/fake-cxl-pool-client
#                   and bin/fake-cxl-pool-controller
#   make test       unit tests
#   make lint       go vet and gofmt check

GO      ?= go
PKG     := github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool
BINDIR  := bin
# the client and the controller run in the VMs: build them static
CLIENT_ENV := CGO_ENABLED=0 GOARCH=amd64

all: $(BINDIR)/fake-cxl-pool-server $(BINDIR)/fake-cxl-pool-client $(BINDIR)/fake-cxl-pool-controller

$(BINDIR)/fake-cxl-pool-server: FORCE
	$(GO) build -o $@ $(PKG)/cmd/fake-cxl-pool-server

$(BINDIR)/fake-cxl-pool-client: FORCE
	$(CLIENT_ENV) $(GO) build -o $@ $(PKG)/cmd/fake-cxl-pool-client

$(BINDIR)/fake-cxl-pool-controller: FORCE
	$(CLIENT_ENV) $(GO) build -o $@ $(PKG)/cmd/fake-cxl-pool-controller

test:
	$(GO) test -race $(PKG)/...

lint:
	$(GO) vet $(PKG)/...
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed: $$out"; exit 1; fi

clean:
	rm -rf $(BINDIR)

.PHONY: all test lint clean FORCE
FORCE:

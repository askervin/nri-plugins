ARG GO_VERSION=1.21

FROM golang:${GO_VERSION}-bullseye as builder

WORKDIR /go/builder

RUN GOBIN=/bin go install github.com/intel/memtierd/cmd/memtierd@latest

# Fetch go dependencies in a separate layer for caching
COPY go.mod go.sum ./
COPY pkg/topology/ pkg/topology/
RUN go mod download

# Build nri-memtierd
COPY . .

RUN make clean
RUN make PLUGINS=nri-memtierd build-plugins-static

# FROM gcr.io/distroless/static
# ENV PATH=/bin

# TODO: DEBUG why exec.Command("memtierd", "-c", ...).Start() fails on distroless:
# execve("/bin/memtierd", ["memtierd", "-c", "", "-config", "/host/tmp/memtierd/default/test-"...], 0xc000146000 /* 38 vars */) = -1 ENOENT (No such file or directory)
# This works on busybox, and /bin/memtierd is there
FROM busybox

COPY --from=builder /go/builder/build/bin/nri-memtierd /bin/nri-memtierd
COPY --from=builder /bin/memtierd /bin/memtierd

ENTRYPOINT ["/bin/nri-memtierd", "--idx", "45"]



# FROM debian:stable-slim

# RUN apt-get update && apt-get install -y software-properties-common build-essential gnupg make curl sudo git socat vim procps

# # Install Go 1.19
# RUN curl -LO https://golang.org/dl/go1.19.linux-amd64.tar.gz && \
#     tar -C /usr/local -xzf go1.19.linux-amd64.tar.gz && \
#     rm go1.19.linux-amd64.tar.gz

# ENV PATH=$PATH:/usr/local/go/bin
# ENV GOPATH=/go
# ENV PATH=$GOPATH/bin:$PATH

# # Get the memtierd binary
# RUN GOBIN=/usr/local/bin go install github.com/intel/memtierd/cmd/memtierd@latest

# # Build the memtierd NRI-plugin binary
# COPY . .
# RUN go mod download
# RUN go build -gcflags "all=-N -l"

# RUN mv memtierd-nri /bin/10-memtierd-nri

# ENTRYPOINT ["10-memtierd-nri"]

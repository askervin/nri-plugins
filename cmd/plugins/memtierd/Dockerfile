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
# execve("/bin/memtierd", ["/bin/memtierd", "-c", "", "-config", "/host/tmp/memtierd/default/test-"...], 0xc000146000 /* 38 vars */) = -1 ENOENT (No such file or directory)
# However, execve works on busybox base image, so let's use it until
# the real problem is solved.

FROM busybox

COPY --from=builder /go/builder/build/bin/nri-memtierd /bin/nri-memtierd
COPY --from=builder /bin/memtierd /bin/memtierd

ENTRYPOINT ["/bin/nri-memtierd", "--idx", "45"]

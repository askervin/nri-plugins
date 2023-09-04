FROM debian:unstable-slim

RUN apt-get update && apt-get install -y golang gnupg curl sudo socat vim procps

ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH

# Get the memtierd binary
RUN GOBIN=/usr/local/bin go install github.com/intel/memtierd/cmd/memtierd@58dd6fe04b64f53121fd29d3156b8760db21940f

# Build the memtierd NRI-plugin binary
COPY . .
RUN go mod download
RUN go build -gcflags "all=-N -l"

RUN mv memtierd-nri /bin/10-memtierd-nri

ENTRYPOINT ["10-memtierd-nri"]

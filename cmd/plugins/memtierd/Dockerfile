FROM debian:stable-slim

RUN apt-get update && apt-get install -y software-properties-common build-essential gnupg make curl sudo git socat vim procps

# Install Go 1.19
RUN curl -LO https://golang.org/dl/go1.19.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.19.linux-amd64.tar.gz && \
    rm go1.19.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH

# Get the memtierd binary
RUN GOBIN=/usr/local/bin go install github.com/intel/memtierd/cmd/memtierd@latest

# Build the memtierd NRI-plugin binary
COPY . .
RUN go mod download
RUN go build -gcflags "all=-N -l"

RUN mv memtierd-nri /bin/10-memtierd-nri

ENTRYPOINT ["10-memtierd-nri"]

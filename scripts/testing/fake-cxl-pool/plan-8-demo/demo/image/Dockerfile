# The image of the pods of the pool-shared-fs demo: python3 for the demo
# tools and mkfs.erofs for the writer. demo setup pool-shared-fs builds it
# (localhost/cxl-demo-tools:<sha256 of this file>) and imports it into
# the nodes as localhost/cxl-demo-tools:demo.
FROM docker.io/library/python:3-alpine
RUN apk add --no-cache erofs-utils

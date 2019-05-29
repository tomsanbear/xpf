# Building the binary
FROM golang:latest as builder

WORKDIR /go/src

RUN git clone https://github.com/coredns/coredns.git && \
    cd coredns && \
    git checkout v1.5.0

ADD plugin.cfg /go/src/coredns/plugin.cfg

WORKDIR /go/src/coredns

RUN GO111MODULE=on GOOS=linux make

# For the certs
FROM debian:stable-slim as certs

RUN apt-get update && apt-get -uy upgrade
RUN apt-get -y install ca-certificates && update-ca-certificates

# The actual docker image
FROM scratch as production

COPY --from=certs /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /go/src/coredns/coredns /coredns

EXPOSE 53 53/udp
ENTRYPOINT ["/coredns"]

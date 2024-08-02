# Build Stage
FROM clux/muslrust:stable AS builder

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_DIR=/etc/ssl/certs

WORKDIR /usr/src/

RUN USER=root cargo new vyos-crowdsec-bouncer
WORKDIR /usr/src/vyos-crowdsec-bouncer
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release

COPY src ./src
RUN cargo install --path .

COPY target/release/vyos-crowdsec-bouncer /usr/bin/vyos-crowdsec-bouncer

# Bundle Stage
FROM gcr.io/distroless/base
COPY --from=0 /usr/bin/vyos-crowdsec-bouncer .
USER 1000
ENTRYPOINT ["/usr/bin/crowdsec-custom-bouncer"]

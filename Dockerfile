# Build Stage
FROM clux/muslrust:stable AS builder

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_DIR=/etc/ssl/certs

WORKDIR /usr/src/
# RUN rustup target add x86_64-unknown-linux-musl

RUN USER=root cargo new vyos-custom-bouncer
WORKDIR /usr/src/voys-custom-bouncer
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release

COPY src ./src
RUN cargo install --path .

## Install crowdsec bouncer
RUN apt-get update && apt-get -y upgrade
RUN curl -s https://install.crowdsec.net | sh
RUN apt-get install -y crowdsec-custom-bouncer

COPY crowdsec-custom-bouncer.yml /etc/crowdsec/bouncers/crowdsec-custom-bouncer.yml

# CMD ["/bin/bash", "-i"]
CMD ["/usr/bin/crowdsec-custom-bouncer", "-c", "/etc/crowdsec/bouncers/crowdsec-custom-bouncer.yml"]

# CMD ["./deciduously-com", "-a", "0.0.0.0", "-p", "8080"]

# Bundle Stage
# FROM distroless/base
# COPY --from=builder /usr/local/cargo/bin/deciduously-com .
# USER 1000
# CMD ["./deciduously-com", "-a", "0.0.0.0", "-p", "8080"]

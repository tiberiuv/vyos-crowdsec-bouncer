FROM clux/muslrust:stable AS planner
ARG REPOSTIORY

RUN cargo install cargo-chef
COPY . .
RUN cargo chef prepare --recipe-path recipe.json


FROM clux/muslrust:stable AS cacher
RUN cargo install cargo-chef
COPY --from=planner /volume/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json


FROM clux/muslrust:stable AS builder
COPY . .
COPY --from=cacher /volume/target target
COPY --from=cacher /root/.cargo /root/.cargo
RUN cargo build --bin vyos-crowdsec-bouncer --release --target x86_64-unknown-linux-musl


# Need cacerts
FROM gcr.io/distroless/static:nonroot
ENV REPOSITORY=$REPOSTIORY
LABEL org.opencontainers.image.source=https://github.com/${REPOSITORY}
COPY --from=builder --chown=nonroot:nonroot /volume/target/x86_64-unknown-linux-musl/release/vyos-crowdsec-bouncer /app/vyos-crowdsec-bouncer
ENTRYPOINT ["/app/vyos-crowdsec-bouncer"]

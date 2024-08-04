FROM gcr.io/distroless/base
COPY --chown=nonroot:nonroot ./vyos-crowdsec-bouncer /app/
USER 1000
ENTRYPOINT ["/app/crowdsec-custom-bouncer"]

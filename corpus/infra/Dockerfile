FROM debian:12-slim

COPY ./bin/billing /usr/local/bin/billing

# deadbolt-expect DB-INF-001:medium
USER root

ENTRYPOINT ["/usr/local/bin/billing"]

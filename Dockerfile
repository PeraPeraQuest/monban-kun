# Dockerfile

# ---------------------------------------------------------------------------
# Build the Monban-kun binary
# ---------------------------------------------------------------------------
FROM rust:1.87-slim-bookworm AS build
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y libssl-dev pkg-config
WORKDIR /build
COPY . .
RUN cargo build --release

# ---------------------------------------------------------------------------
# Publish a container image for Monban-kun
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS image
RUN apt-get update && \
    apt-get install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/monban-kun /usr/local/bin/monban-kun
RUN chmod +x /usr/local/bin/monban-kun
EXPOSE 3000
CMD [ "/usr/local/bin/monban-kun" ]

# Strack with ffmpeg (stream reader and demo servers) and the public live demo as entry point.
# Build from the repository root: docker build -f deploy/Dockerfile -t strack .
FROM rust:1.95-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY assets ./assets
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --create-home --home-dir /app strack
WORKDIR /app
COPY --from=build /src/target/release/strack /usr/local/bin/strack
COPY config ./config
COPY deploy/live-demo.sh deploy/live-config.py ./
RUN chmod +x live-demo.sh && mkdir -p /data && chown strack:strack /data
USER strack
VOLUME ["/data"]
EXPOSE 13000 18100 18200 19180
ENTRYPOINT ["./live-demo.sh"]

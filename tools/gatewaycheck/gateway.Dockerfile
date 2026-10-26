# Private AI Gateway, unmodified, at the commit Phala runs in production
# (inference.phala.com reports it as its source provenance).
FROM rust:1.92 AS build
ARG GATEWAY_COMMIT=22d08e24129804c72b0bfce6f547636992a3f559
RUN git clone --filter=blob:none https://github.com/Dstack-TEE/private-ai-gateway.git /src \
 && git -C /src checkout --quiet "$GATEWAY_COMMIT"
WORKDIR /src
RUN cargo build --release --locked --bin private-ai-gateway \
 && cp target/release/private-ai-gateway /private-ai-gateway

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /private-ai-gateway /usr/local/bin/private-ai-gateway
CMD ["private-ai-gateway"]

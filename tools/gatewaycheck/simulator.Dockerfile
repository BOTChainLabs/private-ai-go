# dstack's TEE simulator, so the gateway can run outside a CVM. Its quotes
# are canned and its keys are fixed test keys: local testing only.
FROM rust:1.92 AS build
ARG DSTACK_COMMIT=05d50dc43efd0350fe0dbcaa2e3c6e1c608d535f
RUN git clone --filter=blob:none https://github.com/Dstack-TEE/dstack.git /src \
 && git -C /src checkout --quiet "$DSTACK_COMMIT"
WORKDIR /src/dstack
# Use the image's toolchain; the repo's toolchain file would download another.
ENV RUSTUP_TOOLCHAIN=1.92.0
RUN cargo build --release --locked -p dstack-guest-agent-simulator \
 && cp target/release/dstack-simulator /dstack-simulator

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /sim
COPY --from=build /dstack-simulator /usr/local/bin/dstack-simulator
COPY --from=build /src/sdk/simulator/dstack.toml /src/sdk/simulator/appkeys.json \
     /src/sdk/simulator/app-compose.json /src/sdk/simulator/sys-config.json \
     /src/sdk/simulator/attestation.bin ./
# Serve the dstack socket in the volume the gateway mounts.
RUN sed -i 's#unix:./dstack.sock#unix:/run/dstack/dstack.sock#' dstack.toml \
 && grep -q 'unix:/run/dstack/dstack.sock' dstack.toml
CMD ["dstack-simulator"]

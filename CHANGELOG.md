# Changelog

All notable changes to this SDK are documented here.

## Unreleased

- E2EE v2 for Phala (`ProviderConfig.E2EE`): message content is encrypted to the gateway's attested X25519 key and answers come back encrypted to a fresh key of each request, buffered and streamed. Receipts are verified against the request as the gateway restores it, which the SDK writes exactly as the gateway's serde_json does.
- Self-hosted gateways (`privateai.Gateway`): a deployment of the open-source Private AI Gateway, such as the BotChain AI Gateway, verified against its own identity (`ProviderConfig.Identity`), always with E2EE. Behind TLS that ends outside the TEE, the attested E2EE key binds the channel.
- `Evidence.E2EE` records the suite content was encrypted with, and `Evidence.TLSPinned` whether the connection was pinned to an attested TLS key.
- A gateway that rotated its E2EE key refuses the request unprocessed; the SDK re-attests and sends it once more.
- Interop and cross-check tools: `tools/gatewaycheck` runs E2EE against the real gateway; `tools/serdecheck` compares the SDK's JSON with serde_json.

## v0.1.0 (2026-10-22)

First public release. Requires Go 1.26 or later.

- Phala (ACI `aci/1`): attestation preflight with workload identity, TLS key pinning, signed receipts over the exact bytes, and streaming.
- NEAR AI: built on NEAR's official Go SDK, with end-to-end encryption, required NVIDIA GPU attestation, workload identity and model-signed responses. A model served from several machines is verified machine by machine.
- Workload identity: the dstack OS build, the provider's apps, and the KMS by its root key. `ProviderConfig.ExtraOSBuilds` and `ExtraAppIDs` accept a confirmed provider upgrade without waiting for a new SDK release.
- Stable error codes, exported from the root package (`privateai.CodeAttestationFailed`, ...).
- Examples: a command-line demo (`examples/demo`) and a chat page that shows each answer's proof (`examples/web`).

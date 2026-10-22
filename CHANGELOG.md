# Changelog

All notable changes to this SDK are documented here.

## Unreleased

First public release candidate.

- Phala (ACI `aci/1`): attestation preflight with workload identity, TLS key pinning, signed receipts over the exact bytes, and streaming.
- NEAR AI: built on NEAR's official Go SDK, with end-to-end encryption, required NVIDIA GPU attestation, workload identity and model-signed responses. A model served from several machines is verified machine by machine.
- Workload identity: the dstack OS build, the provider's apps, and the KMS by its root key. `ProviderConfig.ExtraOSBuilds` and `ExtraAppIDs` accept a confirmed provider upgrade without waiting for a new SDK release.
- Stable error codes, exported from the root package (`privateai.CodeAttestationFailed`, ...).
- Examples: a command-line demo (`examples/demo`) and a chat page that shows each answer's proof (`examples/web`).

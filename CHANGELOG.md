# Changelog

All notable changes to this SDK are documented here.

## Unreleased

- Initial public release candidate.
- Phala (ACI `aci/1`): attestation preflight with workload identity, TLS key pinning, signed receipts over the exact bytes, streaming.
- NEAR AI: built on NEAR's official Go SDK with end-to-end encryption, NVIDIA GPU attestation required, workload identity, and model-signed responses.
- An unknown dstack OS build on NEAR is reported with its measurements. NEAR's model OS build of 2026-10-21 is accepted alongside the previous one.
- Error codes are exported from the root package (`privateai.CodeAttestationFailed`, ...).
- `examples/web`: a chat page that shows each answer's verification.

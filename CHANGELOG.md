# Changelog

All notable changes to this SDK are documented here.

## Unreleased

- Initial public release candidate.
- Phala (ACI `aci/1`): attestation preflight with workload identity, TLS key pinning, signed receipts over the exact bytes, streaming.
- NEAR AI: built on NEAR's official Go SDK with end-to-end encryption, NVIDIA GPU attestation required, workload identity, and model-signed responses.
- The KMS's own build (mr-kms) is no longer pinned by default; the KMS stays pinned by its root key. NEAR upgraded its KMS on 2026-10-21 and served two builds at once.
- An unknown dstack OS build on NEAR is reported with its measurements. NEAR's model OS build of 2026-10-21 is accepted alongside the previous one.
- `ProviderConfig.ExtraOSBuilds` and `ExtraAppIDs` accept a provider OS upgrade or a new NEAR model app without waiting for an SDK release.
- Error codes are exported from the root package (`privateai.CodeAttestationFailed`, ...).
- `examples/web`: a chat page that shows each answer's verification.

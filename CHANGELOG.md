# Changelog

All notable changes to this SDK are documented here.

## Unreleased

- E2EE v2 for Phala (`ProviderConfig.E2EE`): message content is encrypted to the gateway's attested X25519 key and answers come back encrypted to a fresh key of each request, buffered and streamed. Receipts are verified against the request as the gateway restores it, which the SDK writes exactly as the gateway's serde_json does.
- Self-hosted gateways (`privateai.Gateway`): a deployment of the open-source Private AI Gateway, such as the BotChain AI Gateway, verified against its own identity (`ProviderConfig.Identity`), always with E2EE. The identity pins the gateway's releases (`ComposeHashes`, required). TLS must end inside the TEE unless `AllowTLSOutsideTEE` is set: E2EE v2 does not bind the client's key, so whoever terminates TLS could otherwise resend a request with its own key and read the answer.
- `Evidence.E2EE` records the suite content was encrypted with, and `Evidence.TLSPinned` whether the connection was pinned to an attested TLS key.
- A gateway that rotated its E2EE key refuses the request unprocessed; the SDK re-attests and sends it once more.
- The `instance-id` and `gpu-policy-hash` events, now read for MRCONFIGID version 3, must appear at most once in the event log, like the other identity events.
- dstack 0.6 launches (`privateai.Gateway` on Phala Cloud's dstack-0.6.1 image): MRCONFIGID version 3 is verified by rebuilding its document from the attested compose and event log. Version 1, which Phala's own gateway uses, is checked as before.
- Interop and cross-check tools: `tools/gatewaycheck` runs E2EE against the real gateway; `tools/serdecheck` compares the SDK's JSON with serde_json.
- Phala's gateway moved on 2026-11-06 to a new app (`89c51ab8…`), KMS and dstack OS 0.5.12; `phala.ProductionWorkload` accepts it beside the old deployment, which v0.1.0 alone accepts, so v0.1.0 fails to verify `inference.phala.com`.
- Self-hosted gateways default to Phala Cloud's KMS (`phala.CloudKeyProviders`), not to every KMS of Phala's own gateway.
- NEAR's gateway moved to dstack OS 0.5.12 (seen 2026-11-12; `os_image_hash` 8db40cb2…, the production image of meta-dstack's v0.5.12 release, whose NVIDIA image its model VMs already ran): `near.ProductionWorkload` accepts its build beside the earlier one, which alone the SDK accepted before, so NEAR calls failed with "unknown OS build". `TestLiveObserve` (`NEAR_OBSERVE=1`) prints, after full verification, what to pin after such an upgrade.

Security review fixes:

- The serving mode a gateway reports is outside its attestation. It is now trusted only when the report came over a pinned TLS key: with `AllowTLSOutsideTEE`, every receipt must show a verified upstream TEE session, so a gateway in direct mode behind such TLS is refused. A receipt that records upstream attempts needs a verified one even from a direct service, as Phala's verifier requires.
- `phala.ProductionWorkload` binds each of Phala's deployments to its own KMS and OS build (new `phala.Workload.Deployments`); before, any of its apps, key providers and OS builds was accepted with any other. `ExtraOSBuilds` and `ExtraAppIDs` join each deployment.
- A keyset other than the one a request was sent under is trusted for its receipt only within an hour of its attestation, not until its `not_after`.
- `Config.Timeout` bounds a whole Phala or Gateway call, as it did for NEAR, not each HTTP request. For a stream it bounds opening it and `Verify`; reading it is bounded by the caller's context only.
- NEAR refuses a `BaseURL` that is not https; the API key used to go out in clear with an http URL. Neither provider echoes the URL in that error.
- NEAR: every session NEAR's SDK creates must be on a machine the identity check established within the hour, so a prompt is never encrypted to a model key whose app and KMS were not checked, even when the SDK replaces its session just before the send.
- The receipt must state the id it was fetched by; `Evidence.ReceiptID` is now the receipt's own signed id (on the stream fallback it used to be the completion id).
- `Evidence.AdvisoryIDs` records the Intel advisories the TCB status refers to. The default TCB policy still accepts `OutOfDate` (NEAR AI's gateway is `OutOfDate`); set `AcceptedTCBStatuses: []string{"UpToDate"}` to refuse it.
- `examples/web` needs TLS (`-tls-cert`, `-tls-key`) as well as `DEMO_PASSWORD` beyond localhost, takes JSON only, refuses cross-origin requests and, on localhost, requests addressed to other host names.

## v0.1.0 (2026-10-22)

First public release. Requires Go 1.26 or later.

- Phala (ACI `aci/1`): attestation preflight with workload identity, TLS key pinning, signed receipts over the exact bytes, and streaming.
- NEAR AI: built on NEAR's official Go SDK, with end-to-end encryption, required NVIDIA GPU attestation, workload identity and model-signed responses. A model served from several machines is verified machine by machine.
- Workload identity: the dstack OS build, the provider's apps, and the KMS by its root key. `ProviderConfig.ExtraOSBuilds` and `ExtraAppIDs` accept a confirmed provider upgrade without waiting for a new SDK release.
- Stable error codes, exported from the root package (`privateai.CodeAttestationFailed`, ...).
- Examples: a command-line demo (`examples/demo`) and a chat page that shows each answer's proof (`examples/web`).

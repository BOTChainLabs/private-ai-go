# Private AI SDK for Go

Official Go SDK for calling confidential (TEE) AI inference on [Phala](https://phala.com) and [NEAR AI](https://near.ai) from BOT Chain agents and services.

Every call is verified before its result is returned. Before the prompt is sent, the SDK checks the provider's hardware attestation and which code the provider runs. After the response, it checks the provider's signature over the exact request and response bytes. A result that does not verify is returned as an error; the SDK never falls back to ordinary inference.

[中文说明](README.zh-CN.md)

## Install

```bash
go get github.com/BOTChainLabs/private-ai-go
```

Requires Go 1.25.8 or later.

## Providers

| Provider | Endpoint | Verified before sending | Verified after the response |
| --- | --- | --- | --- |
| Phala | `inference.phala.com` (ACI `aci/1`) | Intel TDX attestation, workload identity (dstack OS build, gateway app, KMS), TLS key pinning | Ed25519 receipt over the exact request and response bytes, attested upstream TEE session |
| NEAR AI | `cloud-api.near.ai` | Intel TDX and NVIDIA GPU attestation, workload identity (dstack OS builds, gateway and model apps, KMS), TLS key pinning, request end-to-end encrypted to the model | Signature by the attested model over the exact bytes |

You bring your own provider API key and the provider bills you directly. The SDK never stores or logs API keys, and prompts go straight to the provider.

## Quick start

```go
client, err := privateai.New(privateai.Config{
    Providers: map[privateai.ProviderID]privateai.ProviderConfig{
        privateai.Phala: {APIKey: os.Getenv("PHALA_API_KEY")},
        privateai.NEAR:  {APIKey: os.Getenv("NEARAI_API_KEY")},
    },
    // Only these models can be called.
    Models: []privateai.ModelEntry{
        {Provider: privateai.Phala, Model: "z-ai/glm-5.3"},
        {Provider: privateai.NEAR, Model: "z-ai/glm-5.3-flash"},
    },
})
if err != nil {
    return err
}
defer client.Close()

res, err := client.Infer(ctx, privateai.InferRequest{
    Provider: privateai.Phala,
    Model:    "z-ai/glm-5.3",
    Messages: []privateai.Message{{Role: "user", Content: "hello"}},
})
if err != nil {
    return err // verification failures end up here too
}
fmt.Println(res.Content) // reaching this line means the result is Verified
```

`InferRequest.Params` (temperature, max_tokens, tools, ...) is passed to the provider unchanged.

## Streaming

Content arrives as it is generated, but **it is not verified until `Verify` succeeds**. Use the text only after that when you need a trustworthy result.

```go
st, err := client.Stream(ctx, req)
if err != nil {
    return err
}
defer st.Close()

var sb strings.Builder
for {
    c, err := st.Recv()
    if errors.Is(err, io.EOF) {
        break
    }
    if err != nil {
        return err
    }
    sb.WriteString(c.Content)
}
if _, err := st.Verify(ctx); err != nil {
    return err // a stream must be read to the end before it can be verified
}
```

NEAR signs streamed responses with its gateway key only, which does not prove the model produced them. For NEAR, `Stream` therefore makes one verified call and returns it as a single chunk.

## Policy

By default only machines with Intel TCB status `UpToDate` or `OutOfDate` are accepted. Tighten it per provider:

```go
privateai.Phala: {
    APIKey: os.Getenv("PHALA_API_KEY"),
    Policy: privateai.Policy{
        AcceptedTCBStatuses: []string{"UpToDate"},
        ComposeHashes:       []string{"4dbdcd4f..."}, // only these application versions
    },
},
```

The production identities of Phala and NEAR AI (OS builds, apps, KMS) are built in. Providers' regular releases need no change. When a provider upgrades its OS, or NEAR AI serves a model as a new app, verification fails safely and the error shows the new values to review and add.

## What `Verified` records

`res.Verification.Evidence` holds what the result was checked against: the provider app, OS image and compose hashes, the TCB status and the signed receipt or signature, ready to archive.

## Errors

Every error unwraps to `*privateai.Error` with a stable `Code`:

| Code | Meaning |
| --- | --- |
| `INVALID_REQUEST` | Invalid request; nothing was sent |
| `MODEL_NOT_ALLOWED` | Model not in the configured list; nothing was sent |
| `ATTESTATION_FAILED` | Attestation or workload identity did not verify |
| `TLS_PIN_MISMATCH` | The server's TLS key is not the attested one; nothing was sent |
| `RECEIPT_INVALID` | The receipt or response signature did not verify |
| `ROUTE_NOT_TEE` | The request was not served by a TEE |
| `EVIDENCE_UNAVAILABLE` | Attestation or signature could not be fetched |
| `VERIFIER_UNAVAILABLE` | An external verifier (Intel collateral, NVIDIA NRAS) is unreachable |
| `PROVIDER_ERROR` | The provider returned an error (authentication, balance, rate limit) |

Errors raised after a request was sent carry a `Verification` with the status (`Failed` or `Unverified`) and the reasons. Cancelling the caller's context returns the context's own error.

## Deployment requirements

- Go 1.25.8 or later.
- NEAR AI's GPU attestation is verified by NVIDIA's service at `nras.attestation.nvidia.com`; the host must be able to reach it. Phala does not need it.

## Security

Keep provider API keys in a server-side secret store; never send them to browsers or agents. See [SECURITY.md](SECURITY.md) for reporting a vulnerability.

## Development

```bash
make check                                                    # gofmt, go vet, go test -race
PRIVATEAI_LIVE=1 go test ./provider/phala -run Live -v        # Phala attestation, no key needed
PHALA_API_KEY=... go test ./provider/phala -run LiveInference -v
NEARAI_API_KEY=... go test ./provider/near -run Live -v
```

The Phala verification is cross-checked against Phala's official TypeScript verifier with [tools/crosscheck](tools/crosscheck/README.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

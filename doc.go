// Package privateai calls confidential (TEE) AI inference at Phala and NEAR
// AI and returns a result only after verifying where and how it was
// produced.
//
// Before a prompt is sent, the provider's attestation is checked: a genuine
// Intel TDX machine, the expected OS build and application, and the TLS key
// the connection is pinned to. After the response, the provider's signature
// over the exact request and response bytes is checked.
//
// A nil error from Infer means the result is Verified. Anything else —
// failed checks, missing evidence, an unreachable attestation service —
// is returned as an error; the SDK never falls back to ordinary inference.
// Errors carry a *Error with a stable Code, except cancellation of the
// caller's context, which is returned as the context's own error.
//
// A Client is safe for concurrent use; a Stream is not.
package privateai

// Package core holds the types shared by the SDK entry point and the provider
// adapters.
package core

import (
	"context"
	"encoding/json"
)

// ProviderID names a confidential inference provider.
type ProviderID string

const (
	Phala ProviderID = "phala"
	NEAR  ProviderID = "near"
)

// Status is the outcome of verifying one inference.
type Status string

const (
	// Verified means every check passed: attestation, channel binding,
	// response signature and route.
	Verified Status = "Verified"
	// Failed means evidence was present but did not check out.
	Failed Status = "Failed"
	// Unverified means evidence was missing or could not be fetched.
	Unverified Status = "Unverified"
)

// Message is one chat message (OpenAI format).
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// InferRequest is one chat completion request. Provider and Model must be
// in the client's model list.
type InferRequest struct {
	Provider ProviderID
	Model    string
	Messages []Message
	// Params is copied into the request body as is (temperature, max_tokens,
	// tools, ...). Keys the SDK controls (model, messages, stream, and for
	// Phala provider) are overwritten. With NEAR, message content and tools
	// are encrypted to the model; other parameters reach the gateway in
	// plaintext.
	Params map[string]any
}

// Usage is the token count the provider reported.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// InferResult is a completed, verified inference.
type InferResult struct {
	Content      string
	Raw          json.RawMessage
	Usage        Usage
	Verification Verification
}

// Verification is the outcome of verifying one inference and the evidence
// it was checked against.
type Verification struct {
	Status   Status
	Provider ProviderID
	Model    string
	// Route describes how the request was actually served.
	Route    string
	Reasons  []string
	Evidence Evidence
}

// Evidence records what a verified call was checked against, for audit.
type Evidence struct {
	// The attested workload.
	AppID       string // the dstack app (Phala's gateway, or the NEAR model app that signed)
	ComposeHash string
	OSImageHash string
	TCBStatus   string

	// The response signature. For Phala, Receipt is the signed receipt and
	// Keyset the canonical keyset whose key signed it, so the signature can
	// be re-checked offline. For NEAR, Receipt is the model's signature.
	KeysetDigest string // Phala
	Keyset       json.RawMessage
	ReceiptID    string
	SessionID    string // Phala: the attested upstream session
	Receipt      json.RawMessage
}

// ModelEntry names a model at a provider.
type ModelEntry struct {
	Provider ProviderID
	Model    string
}

// Chunk is one streamed delta.
type Chunk struct {
	Content string
	// Raw is the JSON payload of the server-sent event.
	Raw json.RawMessage
}

// Provider is implemented once per vendor. Implementations must only return
// a nil error together with a Verified result.
type Provider interface {
	ID() ProviderID
	Infer(ctx context.Context, req InferRequest) (*InferResult, error)
	Stream(ctx context.Context, req InferRequest) (ProviderStream, error)
	// Close releases connections and background work. The provider must
	// not be used afterwards.
	Close() error
}

// ProviderStream is a streamed completion. Content is unverified until the
// stream has been read to io.EOF and Verify has returned a nil error.
// A ProviderStream is not safe for concurrent use.
type ProviderStream interface {
	// Recv returns the next delta, or io.EOF once the stream is complete.
	Recv() (Chunk, error)
	// Verify checks the complete stream. It fails if the stream was not
	// read to the end.
	Verify(ctx context.Context) (*Verification, error)
	// Usage is the token usage reported by the stream, once complete.
	Usage() Usage
	Close() error
}

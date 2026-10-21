package privateai

import (
	"context"
	"errors"
	"testing"
)

func newTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{
		Providers: map[ProviderID]ProviderConfig{Phala: {APIKey: "k"}},
		Models:    []ModelEntry{{Provider: Phala, Model: "z-ai/glm-5.3"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func errCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestModelAllowlist(t *testing.T) {
	_, err := newTestClient(t).Infer(context.Background(), InferRequest{
		Provider: Phala, Model: "openai/gpt-5", Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if errCode(err) != "MODEL_NOT_ALLOWED" {
		t.Fatalf("err = %v", err)
	}
}

func TestStreamChecksAllowlist(t *testing.T) {
	_, err := newTestClient(t).Stream(context.Background(), InferRequest{
		Provider: Phala, Model: "openai/gpt-5", Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if errCode(err) != "MODEL_NOT_ALLOWED" {
		t.Fatalf("err = %v", err)
	}
}

func TestEmptyMessagesRejected(t *testing.T) {
	_, err := newTestClient(t).Infer(context.Background(), InferRequest{Provider: Phala, Model: "z-ai/glm-5.3"})
	if errCode(err) != "INVALID_REQUEST" {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := New(Config{Providers: map[ProviderID]ProviderConfig{Phala: {APIKey: "k"}}}); err == nil {
		t.Fatal("accepted a config with no models")
	}
	if _, err := New(Config{
		Providers: map[ProviderID]ProviderConfig{Phala: {APIKey: "k"}},
		Models:    []ModelEntry{{Provider: NEAR, Model: "x"}},
	}); err == nil {
		t.Fatal("accepted a model for an unconfigured provider")
	}
}

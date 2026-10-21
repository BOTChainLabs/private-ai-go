package privateai

import (
	"context"
	"io"
	"testing"

	"github.com/BOTChainLabs/private-ai-go/core"
)

// buggyProvider returns results with a nil error whatever their status, to
// prove the client never passes an unverified result through.
type buggyProvider struct{ status Status }

func (b buggyProvider) ID() ProviderID { return Phala }
func (b buggyProvider) Close() error   { return nil }

func (b buggyProvider) Infer(context.Context, InferRequest) (*InferResult, error) {
	return &InferResult{Content: "leak", Verification: Verification{Status: b.status}}, nil
}

func (b buggyProvider) Stream(context.Context, InferRequest) (core.ProviderStream, error) {
	return &buggyStream{status: b.status}, nil
}

type buggyStream struct {
	status Status
	sent   bool
}

func (s *buggyStream) Recv() (Chunk, error) {
	if s.sent {
		return Chunk{}, io.EOF
	}
	s.sent = true
	return Chunk{Content: "leak"}, nil
}

func (s *buggyStream) Verify(context.Context) (*Verification, error) {
	return &Verification{Status: s.status}, nil
}
func (s *buggyStream) Usage() Usage { return Usage{TotalTokens: 1} }
func (s *buggyStream) Close() error { return nil }

func clientWith(p core.Provider) *Client {
	m := ModelEntry{Provider: Phala, Model: "m"}
	return &Client{providers: map[ProviderID]core.Provider{Phala: p}, models: []ModelEntry{m}, allowed: map[ModelEntry]bool{m: true}}
}

var guardReq = InferRequest{Provider: Phala, Model: "m", Messages: []Message{{Role: "user", Content: "hi"}}}

func TestClientRefusesUnverifiedResults(t *testing.T) {
	for _, status := range []Status{Failed, Unverified, ""} {
		c := clientWith(buggyProvider{status: status})
		if res, err := c.Infer(context.Background(), guardReq); err == nil || res != nil {
			t.Errorf("Infer passed through status %q", status)
		}
		st, err := c.Stream(context.Background(), guardReq)
		if err != nil {
			t.Fatal(err)
		}
		st.Recv()
		st.Recv()
		if v, err := st.Verify(context.Background()); err == nil || v != nil {
			t.Errorf("Stream.Verify passed through status %q", status)
		}
	}
}

func TestClientPassesVerifiedResults(t *testing.T) {
	c := clientWith(buggyProvider{status: Verified})
	if _, err := c.Infer(context.Background(), guardReq); err != nil {
		t.Fatal(err)
	}
	st, err := c.Stream(context.Background(), guardReq)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if c, err := st.Recv(); err != nil || c.Content != "leak" {
		t.Fatalf("Recv %v %v", c, err)
	}
	if _, err := st.Recv(); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
	if v, err := st.Verify(context.Background()); err != nil || v.Status != Verified || st.Usage().TotalTokens != 1 {
		t.Fatalf("Verify %v %v", v, err)
	}
}

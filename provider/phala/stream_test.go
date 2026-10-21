package phala

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/BOTChainLabs/private-ai-go/core"
)

// readAll drains a stream and returns the concatenated content.
func readAll(t *testing.T, st core.ProviderStream) (string, error) {
	t.Helper()
	var sb strings.Builder
	for {
		c, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return sb.String(), nil
		}
		if err != nil {
			return sb.String(), err
		}
		sb.WriteString(c.Content)
	}
}

func TestStreamVerified(t *testing.T) {
	g := newFakeGateway(t)
	st, err := g.provider(t).Stream(context.Background(), testReq)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := readAll(t, st)
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello from tee" {
		t.Fatalf("content %q", got)
	}
	v, err := st.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != core.Verified || v.Evidence.SessionID == "" || st.Usage().TotalTokens != 7 {
		t.Fatalf("verification %+v, usage %+v", v, st.Usage())
	}
	// Verify is idempotent and needs no second receipt lookup.
	if v2, err := st.Verify(context.Background()); err != nil || v2.Status != core.Verified {
		t.Fatalf("second Verify: %v", err)
	}

	var sent map[string]any
	json.Unmarshal(g.lastReq, &sent)
	opts, _ := sent["stream_options"].(map[string]any)
	if sent["stream"] != true || opts["include_usage"] != true {
		t.Fatalf("request %s", g.lastReq)
	}
}

func TestStreamTamperedFailsVerify(t *testing.T) {
	g := newFakeGateway(t)
	g.tamperResponse = true
	st, err := g.provider(t).Stream(context.Background(), testReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readAll(t, st); err != nil {
		t.Fatal(err)
	}
	_, err = st.Verify(context.Background())
	assertCode(t, err, core.CodeReceiptInvalid)
}

func TestStreamVerifyRequiresCompleteRead(t *testing.T) {
	g := newFakeGateway(t)
	st, err := g.provider(t).Stream(context.Background(), testReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Recv(); err != nil {
		t.Fatal(err)
	}
	st.Close()
	_, err = st.Verify(context.Background())
	assertCode(t, err, core.CodeEvidenceUnavailable)
	var e *core.Error
	errors.As(err, &e)
	if e.Verification == nil || e.Verification.Status != core.Unverified {
		t.Fatalf("verification %+v", e.Verification)
	}
}

func TestStreamReceiptFallsBackToCompletionID(t *testing.T) {
	g := newFakeGateway(t)
	g.noReceiptHeader = true
	st, err := g.provider(t).Stream(context.Background(), testReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readAll(t, st); err != nil {
		t.Fatal(err)
	}
	v, err := st.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.Evidence.ReceiptID != "chatcmpl-1" {
		t.Fatalf("receipt id %q", v.Evidence.ReceiptID)
	}
}

func TestStreamErrorEvent(t *testing.T) {
	g := newFakeGateway(t)
	g.streamError = true
	st, err := g.provider(t).Stream(context.Background(), testReq)
	if err != nil {
		t.Fatal(err)
	}
	_, err = readAll(t, st)
	assertCode(t, err, core.CodeProviderError)
	if _, err := st.Recv(); err == nil {
		t.Fatal("Recv after a failure should keep failing")
	}
	if _, err := st.Verify(context.Background()); err == nil {
		t.Fatal("a failed stream verified")
	}
}

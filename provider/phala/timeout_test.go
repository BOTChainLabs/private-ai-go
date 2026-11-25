package phala

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BOTChainLabs/private-ai-go/core"
)

const shortTimeout = 200 * time.Millisecond

func withTimeout(o *Options) { o.Timeout = shortTimeout }

// within fails unless the step returned well before the stalled endpoint
// (one second) could have answered.
func within(t *testing.T, start time.Time) {
	t.Helper()
	if el := time.Since(start); el > 800*time.Millisecond {
		t.Fatalf("returned after %s; Timeout is %s", el, shortTimeout)
	}
}

// Options.Timeout bounds a non-streaming call as a whole, not each request:
// a receipt that never comes ends the call at the timeout, as an SDK error.
func TestTimeoutBoundsInfer(t *testing.T) {
	g := newFakeGateway(t)
	g.receiptDelay = time.Second
	p := g.provider(t, withTimeout)
	if _, err := p.Attest(context.Background()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := p.Infer(context.Background(), testReq)
	within(t, start)
	e := assertCodeOf(t, err, core.CodeEvidenceUnavailable)
	if e.Verification == nil || e.Verification.Status != core.Unverified {
		t.Fatalf("verification %+v", e.Verification)
	}
}

// For a stream, Timeout bounds opening it, until the response headers
// arrive.
func TestTimeoutBoundsStreamOpening(t *testing.T) {
	g := newFakeGateway(t)
	g.chatDelay = time.Second
	p := g.provider(t, withTimeout)
	if _, err := p.Attest(context.Background()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	st, err := p.Stream(context.Background(), testReq)
	within(t, start)
	if st != nil {
		t.Fatal("stream returned")
	}
	assertCodeOf(t, err, core.CodeProviderError)
}

// Reading a stream is bounded by the caller's context only: an answer that
// takes longer than Timeout to generate is read and verified.
func TestTimeoutDoesNotCutStream(t *testing.T) {
	g := newFakeGateway(t)
	g.partDelay = shortTimeout / 2 // the answer takes three times the timeout
	st, err := g.provider(t, withTimeout).Stream(context.Background(), testReq)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if got, err := readAll(t, st); err != nil || got != "hello from tee" {
		t.Fatalf("%q, %v", got, err)
	}
	if _, err := st.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Stream.Verify is bounded by Timeout as well.
func TestTimeoutBoundsStreamVerify(t *testing.T) {
	g := newFakeGateway(t)
	g.receiptDelay = time.Second
	st, err := g.provider(t, withTimeout).Stream(context.Background(), testReq)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := readAll(t, st); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = st.Verify(context.Background())
	within(t, start)
	assertCodeOf(t, err, core.CodeEvidenceUnavailable)
}

// The caller's own cancellation is still returned as the context's error.
func TestCallerCancellationDuringReceipt(t *testing.T) {
	g := newFakeGateway(t)
	g.receiptDelay = time.Second
	p := g.provider(t)
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err := p.Infer(ctx, testReq)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	var e *core.Error
	if errors.As(err, &e) {
		t.Fatalf("the caller's cancellation became %v", e)
	}
}

func assertCodeOf(t *testing.T, err error, code string) *core.Error {
	t.Helper()
	var e *core.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("err = %v, want code %s", err, code)
	}
	return e
}

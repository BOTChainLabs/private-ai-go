package phala

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/BOTChainLabs/private-ai-go/core"
	"github.com/BOTChainLabs/private-ai-go/internal/e2ee"
	"github.com/BOTChainLabs/private-ai-go/internal/e2ee/e2eetest"
)

func newE2EEGateway(t *testing.T) *fakeGateway {
	g := newFakeGateway(t)
	g.e2ee = e2eetest.NewService(0x03)
	g.rotate(0x07)
	return g
}

func withE2EE(o *Options) { o.E2EE = true }

var secretReq = core.InferRequest{Provider: core.Phala, Model: "m", Messages: []core.Message{{Role: "user", Content: "my secret prompt"}}, Params: map[string]any{"temperature": 0.7}}

func TestE2EEInferVerified(t *testing.T) {
	g := newE2EEGateway(t)
	res, err := g.provider(t, withE2EE).Infer(context.Background(), secretReq)
	if err != nil {
		t.Fatal(err)
	}
	if res.Content != "hello from tee" || res.Verification.Status != core.Verified {
		t.Fatalf("result %+v", res)
	}
	if res.Verification.Evidence.E2EE != e2ee.Algo || !res.Verification.Evidence.TLSPinned {
		t.Fatalf("evidence %+v", res.Verification.Evidence)
	}
	if !bytes.Contains(res.Raw, []byte(`"content":"hello from tee"`)) {
		t.Fatalf("Raw is not decrypted: %s", res.Raw)
	}
	if bytes.Contains(g.lastWire, []byte("secret")) {
		t.Fatalf("prompt sent in plaintext: %s", g.lastWire)
	}
	if !bytes.Contains(g.lastReq, []byte("my secret prompt")) || !bytes.Contains(g.lastWire, []byte(`"temperature":0.7`)) {
		t.Fatalf("gateway restored %s from %s", g.lastReq, g.lastWire)
	}
	if bytes.Contains(g.lastResp, []byte("hello")) {
		t.Fatalf("answer returned in plaintext: %s", g.lastResp)
	}
}

func TestE2EEStreamVerified(t *testing.T) {
	g := newE2EEGateway(t)
	st, err := g.provider(t, withE2EE).Stream(context.Background(), secretReq)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var got strings.Builder
	for {
		c, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got.WriteString(c.Content)
		if bytes.Contains(c.Raw, []byte(`"content":"`)) && !bytes.Contains(c.Raw, []byte(c.Content)) {
			t.Fatalf("chunk Raw not decrypted: %s", c.Raw)
		}
	}
	if got.String() != "hello from tee" {
		t.Fatalf("content %q", got.String())
	}
	v, err := st.Verify(context.Background())
	if err != nil || v.Evidence.E2EE != e2ee.Algo || st.Usage().TotalTokens != 7 {
		t.Fatalf("verify %+v, %v, usage %+v", v, err, st.Usage())
	}
}

// Behind a TLS terminator the keyset lists no TLS key: that is accepted
// only when asked for (Gateway), and only with E2EE.
func TestE2EEBindsChannelWithoutTLSKey(t *testing.T) {
	g := newE2EEGateway(t)
	g.noTLSKey = true
	g.rotate(0x07)
	unpinned := func(o *Options) { o.UnpinnedTLS = true }
	res, err := g.provider(t, withE2EE, unpinned).Infer(context.Background(), secretReq)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verification.Evidence.TLSPinned {
		t.Fatal("evidence claims a pinned TLS key")
	}
	// Phala serves its own TLS: E2EE alone does not relax pinning.
	_, err = g.provider(t, withE2EE).Infer(context.Background(), secretReq)
	assertCode(t, err, core.CodeAttestationFailed)
	_, err = g.provider(t).Infer(context.Background(), secretReq)
	assertCode(t, err, core.CodeAttestationFailed)
	if _, err := New(Options{APIKey: "k", UnpinnedTLS: true}); err == nil {
		t.Fatal("UnpinnedTLS accepted without E2EE")
	}
}

// A keyset may list suites this SDK does not know, in shapes it does not
// know; they are ignored, with and without E2EE (spec §3.1).
func TestUnknownE2EESuiteIsIgnored(t *testing.T) {
	g := newE2EEGateway(t)
	g.futureSuite = true
	g.rotate(0x07)
	if _, err := g.provider(t).Infer(context.Background(), secretReq); err != nil {
		t.Fatal(err)
	}
	if _, err := g.provider(t, withE2EE).Infer(context.Background(), secretReq); err != nil {
		t.Fatal(err)
	}
}

func TestE2EERequiresAttestedSupport(t *testing.T) {
	g := newFakeGateway(t) // advertises no E2EE and publishes no key
	_, err := g.provider(t, withE2EE).Infer(context.Background(), secretReq)
	assertCode(t, err, core.CodeAttestationFailed)
	if n := g.chats.Load(); n != 0 {
		t.Fatalf("%d requests sent without an attested E2EE key", n)
	}
}

// The gateway rotates its E2EE key after the preflight. It refuses the
// request without processing it, so the SDK attests the new key and sends
// the request once more.
func TestE2EEKeyRotationIsReattested(t *testing.T) {
	g := newE2EEGateway(t)
	p := g.provider(t, withE2EE)
	if _, err := p.Attest(context.Background()); err != nil {
		t.Fatal(err)
	}
	g.e2ee = e2eetest.NewService(0x04)
	g.rotate(0x08)
	if _, err := p.Infer(context.Background(), secretReq); err != nil {
		t.Fatal(err)
	}
	if a, c := g.attestations.Load(), g.chats.Load(); a != 2 || c != 2 {
		t.Fatalf("%d attestations and %d requests, want 2 and 2", a, c)
	}
}

func TestE2EEPlaintextAnswerIsRefused(t *testing.T) {
	g := newE2EEGateway(t)
	g.plainResponse = true
	_, err := g.provider(t, withE2EE).Infer(context.Background(), secretReq)
	assertCode(t, err, core.CodeProviderError)
}

// The receipt binds the request the gateway restored: had it restored
// anything other than what the client predicted, the receipt fails.
func TestE2EEReceiptBindsRestoredRequest(t *testing.T) {
	g := newE2EEGateway(t)
	p := g.provider(t, withE2EE)
	if _, err := p.Infer(context.Background(), secretReq); err != nil {
		t.Fatal(err)
	}
	s, err := p.session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ex := &exchange{s: s, hashed: bytes.Replace(g.lastReq, []byte("secret"), []byte("other"), 1)}
	_, err = p.verify(context.Background(), context.Background(), ex, "rcpt-1", false, "m", g.lastResp)
	assertCode(t, err, core.CodeReceiptInvalid)
}

func TestGatewayIDNeedsItsOwnIdentity(t *testing.T) {
	if _, err := New(Options{ID: core.Gateway, APIKey: "k", BaseURL: "https://gw.example"}); err == nil {
		t.Error("a gateway without a workload was accepted")
	}
	if _, err := New(Options{ID: core.Gateway, APIKey: "k", Workload: &fakeWorkload}); err == nil {
		t.Error("a gateway without a base URL was accepted")
	}
	// An empty identity would accept any app on any OS.
	for _, w := range []Workload{{}, {OS: fakeWorkload.OS, AppIDs: fakeWorkload.AppIDs}, {OS: fakeWorkload.OS, KeyProviders: fakeWorkload.KeyProviders}} {
		if _, err := New(Options{ID: core.Gateway, APIKey: "k", BaseURL: "https://gw.example", Workload: &w}); err == nil {
			t.Errorf("a gateway with workload %+v was accepted", w)
		}
	}
}

func TestGatewayResultsCarryItsID(t *testing.T) {
	g := newE2EEGateway(t)
	p := g.provider(t, withE2EE, func(o *Options) { o.ID = core.Gateway })
	res, err := p.Infer(context.Background(), secretReq)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verification.Provider != core.Gateway || res.Verification.Route != "gateway-aci" || p.ID() != core.Gateway {
		t.Fatalf("verification %+v", res.Verification)
	}
}

func TestE2EEHeadersSent(t *testing.T) {
	g := newE2EEGateway(t)
	var seen http.Header
	g.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" {
			seen = r.Header.Clone()
		}
		g.serve(w, r)
	})
	if _, err := g.provider(t, withE2EE).Infer(context.Background(), secretReq); err != nil {
		t.Fatal(err)
	}
	if seen.Get("X-E2EE-Version") != "2" || seen.Get("X-Model-Pub-Key") != g.e2ee.PublicHex() || seen.Get("X-Signing-Algo") != "" {
		t.Fatalf("headers %v", seen)
	}
}

// service_capabilities is outside the attested keyset. Behind TLS that ends
// outside the TEE, whoever terminates it can rewrite it, so a reported
// "direct" must not waive the receipt's verified upstream session.
func TestUnpinnedIgnoresReportedServing(t *testing.T) {
	unpinned := func(o *Options) { o.UnpinnedTLS = true }
	for _, upstream := range []string{"failed", "none"} {
		t.Run(upstream, func(t *testing.T) {
			g := newE2EEGateway(t)
			g.noTLSKey = true
			g.serving = "direct"
			g.upstream = upstream
			g.rotate(0x07)
			_, err := g.provider(t, withE2EE, unpinned).Infer(context.Background(), secretReq)
			assertCode(t, err, core.CodeReceiptInvalid)
		})
	}
}

// Over a pinned TLS key the report comes from the TEE: a direct service's
// receipts carry no upstream event. One that records upstream attempts must
// still show a verified one, as Phala's verifier requires.
func TestPinnedDirectServing(t *testing.T) {
	g := newE2EEGateway(t)
	g.serving = "direct"
	g.upstream = "none"
	if _, err := g.provider(t, withE2EE).Infer(context.Background(), secretReq); err != nil {
		t.Fatal(err)
	}
	g.upstream = "failed"
	_, err := g.provider(t, withE2EE).Infer(context.Background(), secretReq)
	assertCode(t, err, core.CodeReceiptInvalid)
}

// supported_e2ee_versions is outside the attested keyset as well, but it is
// only ever a reason to refuse: content is encrypted to the keyset's
// attested key, or not sent. A rewritten list cannot make the SDK send
// without that key.
func TestUnpinnedE2EEVersionsCannotRelax(t *testing.T) {
	unpinned := func(o *Options) { o.UnpinnedTLS = true }
	g := newFakeGateway(t) // its keyset lists no E2EE key
	g.noTLSKey = true
	g.versions = []string{"2"}
	g.rotate(0x07)
	_, err := g.provider(t, withE2EE, unpinned).Infer(context.Background(), secretReq)
	assertCode(t, err, core.CodeAttestationFailed)

	h := newE2EEGateway(t)
	h.noTLSKey = true
	h.versions = []string{}
	h.rotate(0x07)
	_, err = h.provider(t, withE2EE, unpinned).Infer(context.Background(), secretReq)
	assertCode(t, err, core.CodeAttestationFailed)
	if n := g.chats.Load() + h.chats.Load(); n != 0 {
		t.Fatalf("%d requests sent", n)
	}
}

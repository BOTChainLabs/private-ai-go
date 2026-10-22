package phala

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BOTChainLabs/private-ai-go/core"
	"github.com/BOTChainLabs/private-ai-go/internal/canon"
	"github.com/BOTChainLabs/private-ai-go/internal/tdx"
)

// fakeGateway is an HTTPS server speaking the ACI endpoints, attesting
// fakeWorkload. The "quote" it serves is just hex(report_data); its quote
// method decodes it and adds the measurements.
type fakeGateway struct {
	srv        *httptest.Server
	appCompose string
	eventLog   string
	rtmr3      []byte

	mu       sync.Mutex
	key      ed25519.PrivateKey
	keyset   json.RawMessage
	digest   string
	pin      string
	domain   string
	lastReq  []byte
	lastResp []byte

	// knobs, set before requests are made
	tamperResponse  bool
	notRequired     bool
	noReceiptHeader bool // receipt is then looked up by completion id
	streamError     bool
	receiptDigest   string // overrides the digest the receipt names
	receipt404      atomic.Int32
	attestations    atomic.Int32
	chats           atomic.Int32 // chat requests received
}

// fakeWorkload is the identity the fake gateway attests: placeholder OS
// measurements, and dstack events measured the way dstack measures them.
var fakeWorkload = Workload{
	OS:              []OSMeasurement{{MRTD: strings.Repeat("11", 48), RTMR0: strings.Repeat("22", 48), RTMR1: strings.Repeat("33", 48), RTMR2: strings.Repeat("44", 48)}},
	AppIDs:          []string{"a1a1a1a1"},
	KeyProviders:    []string{hex.EncodeToString([]byte(`{"name":"kms","id":"fake"}`))},
	KMSMeasurements: []string{strings.Repeat("55", 32)},
}

// dstackEventLog measures name/payload events into RTMR3 as dstack does and
// returns the event log and the resulting RTMR3.
func dstackEventLog(events [][2]string) (string, []byte) {
	rtmr := make([]byte, 48)
	var log []any
	for _, e := range events {
		payload, _ := hex.DecodeString(e[1])
		h := sha512.New384()
		binary.Write(h, binary.LittleEndian, uint32(tdx.DstackEvent))
		h.Write([]byte(":" + e[0] + ":"))
		h.Write(payload)
		digest := h.Sum(nil)
		ext := sha512.New384()
		ext.Write(rtmr)
		ext.Write(digest)
		rtmr = ext.Sum(nil)
		log = append(log, map[string]any{"imr": 3, "event_type": tdx.DstackEvent, "digest": hex.EncodeToString(digest), "event": e[0], "event_payload": e[1]})
	}
	b, _ := json.Marshal(log)
	return string(b), rtmr
}

// sseParts is an OpenAI-style event stream, written one part per flush. It
// includes a keep-alive comment and a usage-only event, as real gateways do.
func sseParts(withError bool) [][]byte {
	parts := []string{
		"data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
		"data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"delta\":{\"content\":\"hello \"}}]}\n\n",
		": keep-alive\n\n",
		"data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"delta\":{\"content\":\"from tee\"}}]}\n\n",
	}
	if withError {
		parts = append(parts, "data: {\"error\":{\"message\":\"upstream reset\",\"type\":\"server_error\"}}\n\n")
	}
	parts = append(parts,
		"data: {\"id\":\"chatcmpl-1\",\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4,\"total_tokens\":7}}\n\n",
		"data: [DONE]\n\n",
	)
	out := make([][]byte, len(parts))
	for i, p := range parts {
		out[i] = []byte(p)
	}
	return out
}

// quote stands in for DCAP verification of the fake gateway's quote.
func (g *fakeGateway) quote(_ context.Context, hexQuote string) (QuoteResult, error) {
	rd, err := hex.DecodeString(hexQuote)
	if err != nil {
		return QuoteResult{}, err
	}
	unhex := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	os := fakeWorkload.OS[0]
	compose := sha256.Sum256([]byte(g.appCompose))
	return QuoteResult{
		TCBStatus:  "UpToDate",
		ReportData: rd,
		MRTD:       unhex(os.MRTD),
		RTMR0:      unhex(os.RTMR0),
		RTMR1:      unhex(os.RTMR1),
		RTMR2:      unhex(os.RTMR2),
		MRConfigID: append(append([]byte{0x01}, compose[:]...), make([]byte, 15)...),
		RTMR3:      g.rtmr3,
	}, nil
}

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	g := &fakeGateway{appCompose: `{"name":"fake-gateway"}`, domain: "127.0.0.1"}
	g.srv = httptest.NewTLSServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	g.pin = SPKIHash(g.srv.Certificate().RawSubjectPublicKeyInfo)
	compose := sha256.Sum256([]byte(g.appCompose))
	g.eventLog, g.rtmr3 = dstackEventLog([][2]string{
		{"app-id", fakeWorkload.AppIDs[0]},
		{"compose-hash", hex.EncodeToString(compose[:])},
		{"mr-kms", fakeWorkload.KMSMeasurements[0]},
		{"key-provider", fakeWorkload.KeyProviders[0]},
	})
	g.rotate(0x07)
	return g
}

// rotate switches the gateway to a new receipt key, and so a new keyset.
func (g *fakeGateway) rotate(seed byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	g.keyset, _ = json.Marshal(map[string]any{
		"subject":              nil,
		"not_after":            time.Now().Add(30 * 24 * time.Hour).Unix(),
		"receipt_signing_keys": []any{map[string]any{"key_id": "k1", "algo": "ed25519", "public_key": hex.EncodeToString(g.key.Public().(ed25519.PublicKey))}},
		"e2ee_public_keys":     []any{},
		"tls_public_keys":      []any{map[string]any{"spki_sha256": g.pin, "domain": g.domain}},
	})
	g.digest, _ = KeysetDigest(g.keyset)
}

func (g *fakeGateway) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	key, keyset, digest := g.key, g.keyset, g.digest
	g.mu.Unlock()
	w.Header().Set("X-ACI-Version", "aci/1")
	w.Header().Set("X-ACI-Keyset-Digest", digest)

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/aci/attestation":
		g.attestations.Add(1)
		nonce := r.URL.Query().Get("nonce")
		rd := ExpectedReportData(digest, &nonce)
		json.NewEncoder(w).Encode(map[string]any{
			"api_version":            "aci/1",
			"workload_keyset_digest": digest,
			"attestation": map[string]any{
				"tee_type":          "tdx",
				"workload_keyset":   keyset,
				"report_data":       hex.EncodeToString(rd[:]),
				"source_provenance": map[string]any{"repo_url": "https://example.com/gw.git", "repo_commit": "abc"},
				"evidence": map[string]any{
					"quote":       hex.EncodeToString(append(rd[:], make([]byte, 32)...)),
					"event_log":   g.eventLog,
					"app_compose": g.appCompose,
				},
			},
			"service_capabilities": map[string]any{"serving": "aggregator"},
		})

	case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
		g.chats.Add(1)
		body, _ := io.ReadAll(r.Body)
		var parsed struct {
			Stream bool `json:"stream"`
		}
		json.Unmarshal(body, &parsed)
		var parts [][]byte
		if parsed.Stream {
			parts = sseParts(g.streamError)
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			parts = [][]byte{[]byte(`{"id":"chatcmpl-1","choices":[{"message":{"role":"assistant","content":"hello from tee"}}],"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`)}
		}
		g.mu.Lock()
		g.lastReq, g.lastResp = body, bytes.Join(parts, nil)
		g.mu.Unlock()
		if !g.noReceiptHeader {
			w.Header().Set("X-Receipt-Id", "rcpt-1")
		}
		for _, part := range parts {
			if g.tamperResponse {
				part = bytes.Replace(part, []byte("hello"), []byte("HELLO"), 1)
			}
			w.Write(part)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}

	case r.Method == http.MethodGet && (r.URL.Path == "/v1/aci/receipts/rcpt-1" || r.URL.Path == "/v1/aci/receipts/chatcmpl-1"):
		if g.receipt404.Load() > 0 {
			g.receipt404.Add(-1)
			http.NotFound(w, r)
			return
		}
		g.mu.Lock()
		req, resp := g.lastReq, g.lastResp
		g.mu.Unlock()
		named := digest
		if g.receiptDigest != "" {
			named = g.receiptDigest
		}
		doc := map[string]any{
			"api_version": "aci/1", "receipt_id": "rcpt-1", "chat_id": "chatcmpl-1", "model": "m",
			"workload_keyset_digest": named, "endpoint": "/v1/chat/completions", "method": "POST",
			"served_at": time.Now().Unix(), "key_id": "k1",
			"event_log": []any{
				map[string]any{"type": "request.received", "body_hash": BodyHash(req)},
				map[string]any{"type": "upstream.verified", "result": "verified", "required": !g.notRequired, "model_id": "m", "session_id": strings.Repeat("ab", 32)},
				map[string]any{"type": "response.returned", "body_hash": BodyHash(resp)},
			},
		}
		raw, _ := json.Marshal(doc)
		signed, _ := canon.Canonicalize(raw)
		doc["signature"] = hex.EncodeToString(ed25519.Sign(key, signed))
		json.NewEncoder(w).Encode(doc)

	default:
		http.NotFound(w, r)
	}
}

func (g *fakeGateway) provider(t *testing.T, opts ...func(*Options)) *Provider {
	t.Helper()
	o := Options{
		APIKey:        "test-key",
		BaseURL:       g.srv.URL,
		QuoteVerifier: g.quote,
		Workload:      &fakeWorkload,
		Transport:     g.srv.Client().Transport.(*http.Transport),
	}
	for _, f := range opts {
		f(&o)
	}
	p, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var testReq = core.InferRequest{Provider: core.Phala, Model: "m", Messages: []core.Message{{Role: "user", Content: "hi"}}}

func TestInferVerified(t *testing.T) {
	g := newFakeGateway(t)
	res, err := g.provider(t).Infer(context.Background(), testReq)
	if err != nil {
		t.Fatal(err)
	}
	if res.Content != "hello from tee" || res.Verification.Status != core.Verified || res.Usage.TotalTokens != 7 {
		t.Fatalf("result %+v", res)
	}
	if res.Verification.Evidence.SessionID == "" || len(res.Verification.Evidence.Receipt) == 0 {
		t.Fatal("evidence missing")
	}
	var sent map[string]any
	json.Unmarshal(g.lastReq, &sent)
	if p, _ := sent["provider"].(map[string]any); p["aci_verified"] != true {
		t.Fatalf("request did not carry aci_verified: %s", g.lastReq)
	}
}

func TestInferRejectsTamperedResponse(t *testing.T) {
	g := newFakeGateway(t)
	g.tamperResponse = true
	_, err := g.provider(t).Infer(context.Background(), testReq)
	assertCode(t, err, core.CodeReceiptInvalid)
}

func TestInferRejectsOptionalUpstream(t *testing.T) {
	g := newFakeGateway(t)
	g.notRequired = true
	_, err := g.provider(t).Infer(context.Background(), testReq)
	assertCode(t, err, core.CodeReceiptInvalid)
}

func TestAttestRejectsWrongTLSKey(t *testing.T) {
	g := newFakeGateway(t)
	g.pin = strings.Repeat("00", 32)
	g.rotate(0x07)
	_, err := g.provider(t).Infer(context.Background(), testReq)
	assertCode(t, err, core.CodeTLSPinMismatch)
}

// The gateway's TLS key changes after the preflight: the prompt must not be
// sent, and the identity must be re-established.
func TestInferRefusesChangedTLSKey(t *testing.T) {
	g := newFakeGateway(t)
	p := g.provider(t)
	id, err := p.Attest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stale := *id
	stale.KeysetDigest = "sha256:" + strings.Repeat("ab", 32)
	stale.TLSPins = []string{strings.Repeat("00", 32)}
	if _, err := p.store(&stale); err != nil {
		t.Fatal(err)
	}
	_, err = p.Infer(context.Background(), testReq)
	assertCode(t, err, core.CodeTLSPinMismatch)
	if n := g.chats.Load(); n != 0 {
		t.Fatalf("%d chat requests reached a server with an unpinned key", n)
	}
	p.mu.Lock()
	current := p.current
	p.mu.Unlock()
	if current != nil {
		t.Fatal("identity kept after a TLS key mismatch")
	}
}

func TestUndomainedTLSKeyAppliesToAnyHost(t *testing.T) {
	g := newFakeGateway(t)
	g.domain = ""
	g.rotate(0x07)
	if _, err := g.provider(t).Infer(context.Background(), testReq); err != nil {
		t.Fatal(err)
	}
}

// After the first preflight the gateway rotates its keyset. The receipt is
// signed under the new keyset, which the SDK establishes before trusting it.
func TestKeysetRotationIsReestablished(t *testing.T) {
	g := newFakeGateway(t)
	p := g.provider(t)
	if _, err := p.Attest(context.Background()); err != nil {
		t.Fatal(err)
	}
	g.rotate(0x08)
	res, err := p.Infer(context.Background(), testReq)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verification.Evidence.KeysetDigest != g.digest || g.attestations.Load() != 2 {
		t.Fatalf("digest %s (want %s), attestations %d", res.Verification.Evidence.KeysetDigest, g.digest, g.attestations.Load())
	}
}

func TestReceiptNamingUnknownKeysetIsUnverified(t *testing.T) {
	g := newFakeGateway(t)
	g.receiptDigest = "sha256:" + strings.Repeat("00", 32)
	_, err := g.provider(t).Infer(context.Background(), testReq)
	assertCode(t, err, core.CodeEvidenceUnavailable)
	var e *core.Error
	errors.As(err, &e)
	if e.Verification == nil || e.Verification.Status != core.Unverified {
		t.Fatalf("verification %+v", e.Verification)
	}
}

func TestReceiptLookupRetries(t *testing.T) {
	g := newFakeGateway(t)
	g.receipt404.Store(1)
	if _, err := g.provider(t).Infer(context.Background(), testReq); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentCallsShareOnePreflight(t *testing.T) {
	g := newFakeGateway(t)
	slowQuote := func(ctx context.Context, q string) (QuoteResult, error) {
		time.Sleep(100 * time.Millisecond)
		return g.quote(ctx, q)
	}
	p := g.provider(t, func(o *Options) { o.QuoteVerifier = slowQuote })
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Attest(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := g.attestations.Load(); n != 1 {
		t.Fatalf("%d preflights, want 1", n)
	}
}

func TestCallerCanStopWaitingForPreflight(t *testing.T) {
	g := newFakeGateway(t)
	release := make(chan struct{})
	defer close(release)
	blocked := func(ctx context.Context, q string) (QuoteResult, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return QuoteResult{}, errors.New("released")
	}
	p := g.provider(t, func(o *Options) { o.QuoteVerifier = blocked })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := p.Infer(ctx, testReq)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("err = %v after %s", err, time.Since(start))
	}
}

func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *core.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("err = %v, want code %s", err, code)
	}
}

// TestLiveAttestation runs the real preflight against inference.phala.com:
// fresh nonce, Intel DCAP quote verification, bindings, compose hash, TLS
// pin. The attestation endpoint is public, so no real API key is needed.
func TestLiveAttestation(t *testing.T) {
	if os.Getenv("PRIVATEAI_LIVE") == "" {
		t.Skip("set PRIVATEAI_LIVE=1 to run against inference.phala.com")
	}
	p, err := New(Options{APIKey: "unused-for-attestation"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	id, err := p.Attest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("verified keyset %s (not_after %s)", id.KeysetDigest, id.NotAfter.UTC())
	t.Logf("TCB %s, compose %s, serving %s", id.TCBStatus, id.ComposeHash, id.Serving)
	t.Logf("source %s@%s, TLS pins %v", id.RepoURL, id.RepoCommit, id.TLSPins)
}

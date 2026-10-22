package near

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nearai "github.com/nearai/inference-sdk/go"

	"github.com/BOTChainLabs/private-ai-go/core"
)

// fakeClient stands in for NEAR's SDK: its HTTP client reaches a local
// server, and Verify and VerifyResponse return whatever the test sets.
type fakeClient struct {
	srv       *httptest.Server
	transport http.RoundTripper // overrides the server, for transport errors
	session   nearai.AttestationVerificationResult
	verify    func(id string) (nearai.VerifiedCompletionResult, error)
	src       *fakeSource
	requests  atomic.Int32 // chat requests that reached the server

	mu       sync.Mutex
	verified []string
	closed   bool
}

func (f *fakeClient) Verify(context.Context, string) (nearai.AttestationVerificationResult, error) {
	return f.session, nil
}

// fakeSource serves the real NEAR attestations saved in testdata.
type fakeSource struct {
	// hang makes gateway fetches block until their context ends; released
	// counts the fetches that have returned.
	hang     bool
	released atomic.Int32

	fetches atomic.Int32
	gateway nearai.Attestation
	models  []nearai.Attestation
	// machines, when set, are reported in turn by successive model fetches,
	// as NEAR's load balancer does.
	machines [][]nearai.Attestation
	next     atomic.Int32
}

func (s *fakeSource) FetchGatewayAttestation(ctx context.Context, _ nearai.FetchOptions) (nearai.FetchedGatewayAttestation, error) {
	s.fetches.Add(1)
	if s.hang {
		<-ctx.Done()
		s.released.Add(1)
		return nearai.FetchedGatewayAttestation{}, ctx.Err()
	}
	return nearai.FetchedGatewayAttestation{Attestation: s.gateway}, nil
}

func (s *fakeSource) FetchModelAttestations(context.Context, string, nearai.FetchOptions) (nearai.FetchedModelAttestations, error) {
	if len(s.machines) > 0 {
		n := int(s.next.Add(1)-1) % len(s.machines)
		return nearai.FetchedModelAttestations{Attestations: s.machines[n]}, nil
	}
	return nearai.FetchedModelAttestations{Attestations: s.models}, nil
}

func loadAttestation(name string) nearai.Attestation {
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		panic(err)
	}
	var a nearai.Attestation
	if err := json.Unmarshal(b, &a); err != nil {
		panic(err)
	}
	return a
}

// Real NEAR AI Cloud attestations, captured 2026-10-21. They load on first
// use, so the live tests also run from a compiled test binary on a host
// without the testdata directory.
var (
	fixtureGateway = sync.OnceValue(func() nearai.Attestation { return loadAttestation("gateway-attestation.json") })
	fixtureModel   = sync.OnceValue(func() nearai.Attestation { return loadAttestation("model-attestation.json") })
)

const fakeGatewaySPKI = "aa11"

// newIdentity checks the fixtures with the production workload. The quote,
// binding and GPU checks are NEAR's SDK's; the fakes accept them.
func newFakeIdentity(src *fakeSource) *identity {
	return newIdentity(src,
		func(context.Context, nearai.Attestation, nearai.ClientBinding) (nearai.VerifiedAttestation, error) {
			return nearai.VerifiedAttestation{SPKIFingerprint: fakeGatewaySPKI}, nil
		},
		func(_ context.Context, a nearai.Attestation, _ nearai.ClientBinding) (nearai.VerifiedAttestation, error) {
			return nearai.VerifiedAttestation{Signer: a.Signer}, nil
		},
		ProductionWorkload())
}

func (f *fakeClient) HTTPClient() *http.Client {
	if f.transport != nil {
		return &http.Client{Transport: f.transport}
	}
	return f.srv.Client()
}
func (f *fakeClient) BaseURL() string { return f.srv.URL + "/v1/" }
func (f *fakeClient) Close() error    { f.closed = true; return nil }
func (f *fakeClient) VerifyResponse(_ context.Context, id string) (nearai.VerifiedCompletionResult, error) {
	f.mu.Lock()
	f.verified = append(f.verified, id)
	f.mu.Unlock()
	return f.verify(id)
}

type gatewayKnobs struct {
	servingProvider string
	status          int
}

func newFake(t *testing.T, k gatewayKnobs) (*fakeClient, *Provider) {
	t.Helper()
	f := &fakeClient{verify: verified("provider_tee")}
	f.src = &fakeSource{gateway: fixtureGateway(), models: []nearai.Attestation{fixtureModel()}}
	f.session = nearai.AttestationVerificationResult{
		Gateway: &nearai.VerifiedAttestation{SPKIFingerprint: fakeGatewaySPKI},
		Models:  []nearai.VerifiedAttestation{{Signer: fixtureModel().Signer}},
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		f.requests.Add(1)
		var body struct {
			Stream bool `json:"stream"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Stream {
			http.Error(w, "the adapter must not request a stream", http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Serving-Provider", "near")
		if k.servingProvider != "" {
			w.Header().Set("X-Serving-Provider", k.servingProvider)
		}
		if k.status != 0 {
			w.WriteHeader(k.status)
			io.WriteString(w, `{"error":{"message":"insufficient credits"}}`)
			return
		}
		io.WriteString(w, `{"id":"chatcmpl-n1","choices":[{"message":{"role":"assistant","content":"hello from near"}}],"usage":{"total_tokens":9}}`)
	}))
	t.Cleanup(f.srv.Close)
	p, err := newWithClient(f, newFakeIdentity(f.src), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return f, p
}

func verified(kind string) func(string) (nearai.VerifiedCompletionResult, error) {
	return func(id string) (nearai.VerifiedCompletionResult, error) {
		return nearai.VerifiedCompletionResult{
			CompletionID:  id,
			SignatureKind: kind,
			Signature:     nearai.CompletionSignature{Kind: kind, Signature: "5167"},
			Attestation: &nearai.VerifiedAttestation{
				Signer:     fixtureModel().Signer,
				TCBStatus:  "UpToDate",
				Deployment: nearai.MeasuredDeployment{RuntimeMeasurements: nearai.RuntimeMeasurements{ComposeHash: "c0ffee"}},
			},
		}, nil
	}
}

var testReq = core.InferRequest{Provider: core.NEAR, Model: "z-ai/glm-5.3-flash", Messages: []core.Message{{Role: "user", Content: "hi"}}}

func assertCode(t *testing.T, err error, code string) *core.Error {
	t.Helper()
	var e *core.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("err = %v, want code %s", err, code)
	}
	return e
}

func TestInferVerified(t *testing.T) {
	_, p := newFake(t, gatewayKnobs{})
	res, err := p.Infer(context.Background(), testReq)
	if err != nil {
		t.Fatal(err)
	}
	v := res.Verification
	if res.Content != "hello from near" || res.Usage.TotalTokens != 9 || v.Status != core.Verified {
		t.Fatalf("result %+v", res)
	}
	if v.Route != "near-provider-tee" || v.Evidence.ReceiptID != "chatcmpl-n1" || v.Evidence.ComposeHash != "c0ffee" || len(v.Evidence.Receipt) == 0 {
		t.Fatalf("verification %+v", v)
	}
}

// A gateway signature proves only that the gateway relayed the bytes; E2EE
// does not authenticate the response. Such a result must not be returned.
func TestInferRefusesGatewayOnlySignature(t *testing.T) {
	f, p := newFake(t, gatewayKnobs{})
	f.verify = verified("gateway")
	res, err := p.Infer(context.Background(), testReq)
	if res != nil {
		t.Fatal("returned a result signed by the gateway only")
	}
	if e := assertCode(t, err, core.CodeRouteNotTEE); e.Verification.Status != core.Unverified {
		t.Fatalf("verification %+v", e.Verification)
	}
}

func TestInferRejectsOtherServingProvider(t *testing.T) {
	f, p := newFake(t, gatewayKnobs{servingProvider: "chutes"})
	_, err := p.Infer(context.Background(), testReq)
	assertCode(t, err, core.CodeRouteNotTEE)
	if len(f.verified) != 0 {
		t.Fatal("verified a response served by a third party")
	}
}

func TestInferHTTPError(t *testing.T) {
	_, p := newFake(t, gatewayKnobs{status: http.StatusPaymentRequired})
	_, err := p.Infer(context.Background(), testReq)
	if e := assertCode(t, err, core.CodeProviderError); !strings.Contains(e.Message, "402") {
		t.Fatalf("message %q", e.Message)
	}
}

func TestVerifyFailures(t *testing.T) {
	cases := []struct {
		name   string
		verify func(string) (nearai.VerifiedCompletionResult, error)
		code   string
		status core.Status
	}{
		{"bad signature", fail(&nearai.Error{Code: "signature.invalid"}), core.CodeReceiptInvalid, core.Failed},
		{"signature not yet available", fail(&nearai.Error{Code: "api.completion_signature_unavailable", Retryable: true}), core.CodeEvidenceUnavailable, core.Unverified},
		{"unknown signature kind", verified("something_else"), core.CodeReceiptInvalid, core.Failed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, p := newFake(t, gatewayKnobs{})
			f.verify = c.verify
			_, err := p.Infer(context.Background(), testReq)
			e := assertCode(t, err, c.code)
			if e.Verification == nil || e.Verification.Status != c.status {
				t.Fatalf("verification %+v", e.Verification)
			}
		})
	}
}

func fail(err error) func(string) (nearai.VerifiedCompletionResult, error) {
	return func(string) (nearai.VerifiedCompletionResult, error) { return nearai.VerifiedCompletionResult{}, err }
}

type errTransport struct{ err error }

func (e errTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, e.err }

// Errors raised by NEAR's transport before sending (attestation, TLS pin,
// route policy) map to SDK codes; context errors pass through unchanged.
func TestTransportErrors(t *testing.T) {
	cases := []struct {
		err  error
		code string
	}{
		{&nearai.Error{Code: "policy.model_attestation_required"}, core.CodeRouteNotTEE},
		{&nearai.Error{Code: "e2ee.model_public_key_required"}, core.CodeRouteNotTEE},
		{&nearai.Error{Code: "binding.spki_fingerprint_mismatch"}, core.CodeTLSPinMismatch},
		{&nearai.Error{Code: "quote.verification_failed"}, core.CodeAttestationFailed},
		{&nearai.Error{Code: "measurement.rtmr3_mismatch"}, core.CodeAttestationFailed},
		{&nearai.Error{Code: "quote.collateral_unavailable", Retryable: true}, core.CodeVerifierUnavailable},
		{&nearai.Error{Code: "gpu.nras_request_failed", Details: map[string]any{"status": 403}}, core.CodeVerifierUnavailable},
		{&nearai.Error{Code: "gpu.attestation_rejected"}, core.CodeAttestationFailed},
		{&nearai.Error{Code: "e2ee.decryption_failed"}, core.CodeReceiptInvalid},
		{&nearai.Error{Code: "api.invalid_input"}, core.CodeInvalidRequest},
		{errors.New("connection refused"), core.CodeProviderError},
	}
	for _, c := range cases {
		t.Run(fmt.Sprint(c.err), func(t *testing.T) {
			f, p := newFake(t, gatewayKnobs{})
			f.transport = errTransport{c.err}
			_, err := p.Infer(context.Background(), testReq)
			assertCode(t, err, c.code)
		})
	}

	f, p := newFake(t, gatewayKnobs{})
	f.transport = errTransport{context.Canceled}
	if _, err := p.Infer(context.Background(), testReq); !errors.Is(err, context.Canceled) {
		t.Fatalf("context error changed: %v", err)
	}
}

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

// NEAR streams carry gateway signatures only, so Stream serves a verified
// non-streaming call as a single chunk.
func TestStreamServesVerifiedResult(t *testing.T) {
	f, p := newFake(t, gatewayKnobs{})
	st, err := p.Stream(context.Background(), testReq)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Verify(context.Background()); err == nil {
		t.Fatal("Verify succeeded before the stream was read")
	}
	got, err := readAll(t, st)
	if err != nil || got != "hello from near" {
		t.Fatalf("content %q, %v", got, err)
	}
	v, err := st.Verify(context.Background())
	if err != nil || v.Status != core.Verified || st.Usage().TotalTokens != 9 {
		t.Fatalf("Verify %+v %v, usage %+v", v, err, st.Usage())
	}
	if len(f.verified) != 1 || f.verified[0] != "chatcmpl-n1" {
		t.Fatalf("verified ids %v", f.verified)
	}
}

func TestStreamRefusesUnverifiedResult(t *testing.T) {
	f, p := newFake(t, gatewayKnobs{})
	f.verify = verified("gateway")
	if st, err := p.Stream(context.Background(), testReq); st != nil || err == nil {
		t.Fatal("stream opened over an unverified result")
	}
}

// New builds a real NEAR client without touching the network.
func TestNewBuildsGatewayClient(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("accepted an empty API key")
	}
	p, err := New(Options{APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.chatURL != "https://cloud-api.near.ai/v1/chat/completions" {
		t.Fatalf("chat URL %s", p.chatURL)
	}
}

// TestLive calls NEAR AI Cloud for real: attestation, E2EE, inference and
// signature verification, for both a plain and a streamed completion.
func TestLive(t *testing.T) {
	key := os.Getenv("NEARAI_API_KEY")
	if key == "" {
		t.Skip("set NEARAI_API_KEY to run against NEAR AI Cloud")
	}
	model := os.Getenv("NEARAI_MODEL")
	if model == "" {
		model = testReq.Model
	}
	p, err := New(Options{APIKey: key})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	req := core.InferRequest{Provider: core.NEAR, Model: model, Messages: []core.Message{{Role: "user", Content: "Reply with one short sentence."}}}

	res, err := p.Infer(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	ev := res.Verification.Evidence
	t.Logf("infer: %q (%s, TCB %s)", res.Content, res.Verification.Route, ev.TCBStatus)
	// Values to pin in a NEAR deployment policy.
	t.Logf("model deployment: compose %s, OS image %s", ev.ComposeHash, ev.OSImageHash)

	st, err := p.Stream(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := readAll(t, st)
	if err != nil {
		t.Fatal(err)
	}
	v, err := st.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("stream: %q (%s)", got, v.Route)
}

// TestLiveIdentity establishes, against NEAR AI Cloud, which code serves the
// model: real DCAP verification of the gateway and model reports, then the
// OS builds, dstack apps and KMS of ProductionWorkload. It needs no NVIDIA
// access, so it also runs where NRAS is blocked.
func TestLiveIdentity(t *testing.T) {
	key := os.Getenv("NEARAI_API_KEY")
	if key == "" {
		t.Skip("set NEARAI_API_KEY to run against NEAR AI Cloud")
	}
	p, err := New(Options{APIKey: key})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	e, err := p.ident.get(ctx, testReq.Model)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("established: model signers and apps %v, gateway TLS keys %v", e.apps, e.gatewaySPKIs)
}

package near

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	nearai "github.com/nearai/inference-sdk/go"

	"github.com/BOTChainLabs/private-ai-go/core"
	"github.com/BOTChainLabs/private-ai-go/internal/tdx"
)

// The production workload accepts the real NEAR gateway and model reports.
func TestCheckAppOnRealAttestations(t *testing.T) {
	w := ProductionWorkload()
	if id, err := checkApp(fixtureModel(), w.OS, w.Model); err != nil || id != "2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b" {
		t.Fatalf("model: %q, %v", id, err)
	}
	if id, err := checkApp(fixtureGateway(), w.OS, w.Gateway); err != nil || id != "f550fdfb4eb8ad787c1bcd423f091cbb4a4431ae" {
		t.Fatalf("gateway: %q, %v", id, err)
	}
	// The gateway is not a model app.
	if _, err := checkApp(fixtureGateway(), w.OS, w.Model); err == nil {
		t.Fatal("gateway report accepted as a model app")
	}
}

func TestCheckAppRejects(t *testing.T) {
	w := ProductionWorkload()
	otherApp := w.Model
	otherApp.AppIDs = []string{"00"}
	otherKMS := w.Model
	otherKMS.KMSMeasurements = []string{"00"}
	tampered := fixtureModel()
	tampered.EventLog = json.RawMessage(strings.Replace(string(fixtureModel().EventLog),
		"2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b", "2c0a0c96cb6dbd659bf1446e2f3fce58172ff91c", 1))

	cases := []struct {
		name string
		a    nearai.Attestation
		os   []tdx.OSMeasurement
		app  tdx.App
		want string
	}{
		{"other app", fixtureModel(), w.OS, otherApp, "unexpected app-id"},
		{"other KMS", fixtureModel(), w.OS, otherKMS, "unexpected mr-kms"},
		{"other OS", fixtureModel(), w.OS[:1], w.Model, "unknown OS build"},
		{"payload swapped", tampered, w.OS, w.Model, "RTMR3"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := checkApp(c.a, c.os, c.app); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestOSQuoteVerifier(t *testing.T) {
	m, err := tdx.ParseHexQuote(fixtureModel().IntelQuote)
	if err != nil {
		t.Fatal(err)
	}
	inner := func(context.Context, string) (nearai.QuoteVerificationResult, error) {
		return nearai.QuoteVerificationResult{TCBStatus: "UpToDate", RTMR3: m.RTMR3, ReportData: m.ReportData}, nil
	}
	w := ProductionWorkload()
	if _, err := osQuoteVerifier(inner, w.OS)(context.Background(), fixtureModel().IntelQuote); err != nil {
		t.Fatal(err)
	}
	if _, err := osQuoteVerifier(inner, w.OS[:1])(context.Background(), fixtureModel().IntelQuote); err == nil {
		t.Fatal("unknown OS build accepted")
	}
	lying := func(context.Context, string) (nearai.QuoteVerificationResult, error) {
		return nearai.QuoteVerificationResult{RTMR3: make([]byte, 48), ReportData: m.ReportData}, nil
	}
	if _, err := osQuoteVerifier(lying, w.OS)(context.Background(), fixtureModel().IntelQuote); err == nil {
		t.Fatal("verifier and parser disagreement accepted")
	}
}

// The prompt must only ever be encrypted to identity-checked keys: a session
// using another model signer or gateway is refused before anything is sent.
func TestSessionMustUseEstablishedKeys(t *testing.T) {
	t.Run("model signer", func(t *testing.T) {
		f, p := newFake(t, gatewayKnobs{})
		f.session.Models = []nearai.VerifiedAttestation{{Signer: nearai.SigningIdentity{SigningAlgo: nearai.Ed25519, SigningAddress: "beef"}}}
		_, err := p.Infer(context.Background(), testReq)
		assertCode(t, err, core.CodeAttestationFailed)
		if f.requests.Load() != 0 {
			t.Fatal("request sent under an unchecked model key")
		}
		if n := f.src.fetches.Load(); n != 1+learnRounds {
			t.Fatalf("%d identity rounds, want %d", n, 1+learnRounds)
		}
	})
	t.Run("gateway", func(t *testing.T) {
		f, p := newFake(t, gatewayKnobs{})
		f.session.Gateway = &nearai.VerifiedAttestation{SPKIFingerprint: "bb22"}
		_, err := p.Infer(context.Background(), testReq)
		assertCode(t, err, core.CodeAttestationFailed)
		if f.requests.Load() != 0 {
			t.Fatal("request sent through an unchecked gateway")
		}
	})
}

// NEAR serves a model from two machines and each attestation fetch reports
// one. A session on the machine the first fetch did not show is established
// by fetching again, and both machines stay established.
func TestSessionOnAnotherMachine(t *testing.T) {
	f, p := newFake(t, gatewayKnobs{})
	b := fixtureModel()
	b.Signer = nearai.SigningIdentity{SigningAlgo: nearai.Ed25519, SigningAddress: "b0b0"}
	f.src.machines = [][]nearai.Attestation{{fixtureModel()}, {b}}
	f.session.Models = []nearai.VerifiedAttestation{{Signer: b.Signer}}
	f.verify = func(id string) (nearai.VerifiedCompletionResult, error) {
		r, _ := verified("provider_tee")(id)
		r.Attestation.Signer = b.Signer
		return r, nil
	}
	if _, err := p.Infer(context.Background(), testReq); err != nil {
		t.Fatal(err)
	}
	if n := f.src.fetches.Load(); n != 2 {
		t.Fatalf("%d identity rounds, want 2", n)
	}

	// Back on the first machine: already established, nothing fetched.
	f.session.Models = []nearai.VerifiedAttestation{{Signer: fixtureModel().Signer}}
	f.verify = verified("provider_tee")
	if _, err := p.Infer(context.Background(), testReq); err != nil {
		t.Fatal(err)
	}
	if n := f.src.fetches.Load(); n != 2 {
		t.Fatalf("%d identity rounds, want 2", n)
	}
}

func TestResponseSignerMustBeEstablished(t *testing.T) {
	f, p := newFake(t, gatewayKnobs{})
	f.verify = func(id string) (nearai.VerifiedCompletionResult, error) {
		r, _ := verified("provider_tee")(id)
		r.Attestation.Signer = nearai.SigningIdentity{SigningAlgo: nearai.Ed25519, SigningAddress: "beef"}
		return r, nil
	}
	res, err := p.Infer(context.Background(), testReq)
	if res != nil {
		t.Fatal("returned a result signed by an unchecked key")
	}
	if e := assertCode(t, err, core.CodeAttestationFailed); e.Verification.Status != core.Failed {
		t.Fatalf("verification %+v", e.Verification)
	}
}

func TestIdentityFailureBlocksSend(t *testing.T) {
	f, p := newFake(t, gatewayKnobs{})
	p.ident.workload.Model.AppIDs = []string{"00"}
	_, err := p.Infer(context.Background(), testReq)
	assertCode(t, err, core.CodeAttestationFailed)
	if f.requests.Load() != 0 {
		t.Fatal("request sent although the model app was not NEAR's")
	}
}

// An OS upgrade on NEAR's side is refused with the new measurements named,
// before anything is sent.
func TestUnknownOSBuildIsNamed(t *testing.T) {
	f, p := newFake(t, gatewayKnobs{})
	p.ident.workload.OS = p.ident.workload.OS[:1] // gateway build only
	_, err := p.Infer(context.Background(), testReq)
	e := assertCode(t, err, core.CodeAttestationFailed)
	if !strings.Contains(e.Error(), "unknown OS build: MRTD df4d77c8") {
		t.Fatalf("err = %v", e)
	}
	if f.requests.Load() != 0 {
		t.Fatal("request sent to an unknown OS build")
	}
}

func TestIdentityIsCached(t *testing.T) {
	f, p := newFake(t, gatewayKnobs{})
	for range 3 {
		if _, err := p.Infer(context.Background(), testReq); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.src.fetches.Load(); n != 1 {
		t.Fatalf("identity established %d times, want 1", n)
	}
	res, _ := p.Infer(context.Background(), testReq)
	if res.Verification.Evidence.AppID != "2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b" {
		t.Fatalf("evidence app id %q", res.Verification.Evidence.AppID)
	}
}

// The call's own timeout is not the caller's cancellation: it carries an
// SDK code. Close stops identity work that outlived its call.
func TestIdentityTimeoutAndClose(t *testing.T) {
	f, p := newFake(t, gatewayKnobs{})
	f.src.hang = true
	p.timeout = 50 * time.Millisecond
	_, err := p.Infer(context.Background(), testReq)
	assertCode(t, err, core.CodeEvidenceUnavailable)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Infer(ctx, testReq); !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation: %v", err)
	}

	p.Close()
	deadline := time.Now().Add(2 * time.Second)
	for f.src.released.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if f.src.released.Load() == 0 {
		t.Fatal("identity check still running after Close")
	}
	fetches := f.src.fetches.Load()
	_, err = p.Infer(context.Background(), testReq)
	assertCode(t, err, core.CodeProviderError)
	if f.src.fetches.Load() != fetches || f.requests.Load() != 0 {
		t.Fatal("a closed provider kept working")
	}
}

// A signature that could not be fetched is Unverified; one that was checked
// and did not hold is Failed.
func TestVerifyResponseErrors(t *testing.T) {
	cases := []struct {
		err    error
		code   string
		status core.Status
	}{
		{&nearai.Error{Code: "api.transport_failed", Retryable: true}, core.CodeEvidenceUnavailable, core.Unverified},
		{&nearai.Error{Code: "api.http_status", Details: map[string]any{"status": 503}}, core.CodeEvidenceUnavailable, core.Unverified},
		{context.DeadlineExceeded, core.CodeEvidenceUnavailable, core.Unverified},
		{&nearai.Error{Code: "signature.invalid"}, core.CodeReceiptInvalid, core.Failed},
	}
	for _, c := range cases {
		f, p := newFake(t, gatewayKnobs{})
		f.verify = func(string) (nearai.VerifiedCompletionResult, error) { return nearai.VerifiedCompletionResult{}, c.err }
		_, err := p.Infer(context.Background(), testReq)
		if e := assertCode(t, err, c.code); e.Verification == nil || e.Verification.Status != c.status {
			t.Fatalf("%v: verification %+v", c.err, e.Verification)
		}
	}
}

func TestDetailedNamesHTTPStatus(t *testing.T) {
	err := detailed(&nearai.Error{Code: "api.http_status", Details: map[string]any{"status": 401}})
	if !strings.Contains(err.Error(), "api.http_status (status 401)") || codeFor(err) != core.CodeProviderError {
		t.Fatalf("%v", err)
	}
}

func TestComposeAllowlistIgnoresCase(t *testing.T) {
	check := deploymentPolicy(core.Policy{ComposeHashes: []string{"C0FFEE"}})
	d := nearai.MeasuredDeployment{RuntimeMeasurements: nearai.RuntimeMeasurements{ComposeHash: "c0ffee"}}
	if err := check(context.Background(), "m", d); err != nil {
		t.Fatal(err)
	}
	d.RuntimeMeasurements.ComposeHash = "beef"
	if check(context.Background(), "m", d) == nil {
		t.Fatal("unlisted compose accepted")
	}
}

func TestEstablishedRecordsAppPerSigner(t *testing.T) {
	a := nearai.SigningIdentity{SigningAlgo: nearai.Ed25519, SigningAddress: "AA"}
	b := nearai.SigningIdentity{SigningAlgo: nearai.Ed25519, SigningAddress: "bb"}
	e := &established{apps: map[string]string{signerKey(a): "app-a"}, gatewaySPKIs: []string{"g1"}}
	m := e.merge(&established{apps: map[string]string{signerKey(b): "app-b"}, gatewaySPKIs: []string{"g1", "g2"}})
	if m.appOf(a) != "app-a" || m.appOf(b) != "app-b" || len(m.gatewaySPKIs) != 2 {
		t.Fatalf("merged %+v", m)
	}
	if e.hasSigner(b) || len(e.gatewaySPKIs) != 1 {
		t.Fatal("merge changed the published identity")
	}
	if err := m.checkSession(nearai.AttestationVerificationResult{Models: []nearai.VerifiedAttestation{{Signer: a}}}); err == nil {
		t.Fatal("session without a gateway accepted")
	}
}

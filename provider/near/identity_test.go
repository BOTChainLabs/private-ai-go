package near

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

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

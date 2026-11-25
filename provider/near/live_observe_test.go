package near

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/BOTChainLabs/private-ai-go/core"
	"github.com/BOTChainLabs/private-ai-go/internal/tdx"
	nearai "github.com/nearai/inference-sdk/go"
)

// TestLiveObserve collects what to pin when NEAR changes its deployment (an
// OS upgrade fails TestLiveIdentity with "unknown OS build"). Every report is
// verified in full first, without the OS pins: Intel's DCAP verification of
// the quote and its binding, then NEAR's own app and KMS from the replayed
// RTMR3 event log. Only then are its OS build (MRTD, RTMR0-2) and dstack OS
// image printed, with whether ProductionWorkload pins it already, so that a
// value added to the pins is one a genuine NEAR app ran on.
//
//	NEARAI_API_KEY=... NEAR_OBSERVE=1 go test ./provider/near -run TestLiveObserve -v
//
// NEAR_MODELS (comma-separated) names the models to look at; by default the
// NEAR models the AI Gateway serves.
func TestLiveObserve(t *testing.T) {
	key := os.Getenv("NEARAI_API_KEY")
	if key == "" || os.Getenv("NEAR_OBSERVE") == "" {
		t.Skip("set NEARAI_API_KEY and NEAR_OBSERVE=1 to observe NEAR AI Cloud's deployment")
	}
	models := strings.Split(os.Getenv("NEAR_MODELS"), ",")
	if os.Getenv("NEAR_MODELS") == "" {
		models = []string{testReq.Model, "Qwen/Qwen3.8-27B", "Qwen/Qwen3.6-35B-A3B-FP8", "deepseek-ai/DeepSeek-V4.1-Flash-1017"}
	}
	src, err := nearai.NewAttestationClient(nearai.ClientOptions{APIKey: key})
	if err != nil {
		t.Fatal(err)
	}
	w := ProductionWorkload()
	// What New verifies with, less the OS pins.
	opts := nearai.VerificationOptions{
		Policy:        nearai.AttestationPolicy{AcceptedTCBStatuses: core.Policy{}.TCBStatuses()},
		QuoteVerifier: nearai.CreateTDXQuoteVerifier(""),
		GPUVerifier:   func(context.Context, string) error { return nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	fetch := nearai.FetchOptions{SigningAlgo: nearai.Ed25519}

	g, err := src.FetchGatewayAttestation(ctx, fetch)
	if err != nil {
		t.Fatalf("fetch gateway attestation: %v", err)
	}
	if _, err := nearai.VerifyGatewayAttestation(ctx, g.Attestation, g.ClientBinding, opts); err != nil {
		t.Fatalf("gateway attestation does not verify: %v", err)
	}
	observe(t, "gateway", g.Attestation, w.Gateway, w.OS)

	for _, model := range models {
		m, err := src.FetchModelAttestations(ctx, model, fetch)
		if err != nil {
			t.Errorf("%s: fetch: %v", model, err)
			continue
		}
		if len(m.Attestations) == 0 {
			t.Logf("%s: no TEE attestation (served by a third party): not pinned", model)
			continue
		}
		for _, a := range m.Attestations {
			if _, err := nearai.VerifyModelAttestation(ctx, a, m.ClientBinding, opts); err != nil {
				t.Errorf("%s instance %s does not verify: %v", model, a.InstanceID, err)
				continue
			}
			observe(t, model+" instance "+a.InstanceID, a, w.Model, w.OS)
		}
	}
}

// observe checks that a verified report is NEAR's app under NEAR's KMS and
// prints its OS build.
func observe(t *testing.T, name string, a nearai.Attestation, app tdx.App, pinned []tdx.OSMeasurement) {
	t.Helper()
	m, err := tdx.ParseHexQuote(a.IntelQuote)
	if err != nil {
		t.Errorf("%s: %v", name, err)
		return
	}
	events, err := tdx.ReplayRTMR3(a.EventLog, m.RTMR3)
	if err != nil {
		t.Errorf("%s: event log: %v", name, err)
		return
	}
	if err := app.Check(events); err != nil {
		t.Errorf("%s is not NEAR's app under NEAR's KMS: %v", name, err)
		return
	}
	os := tdx.OSOf(m)
	t.Logf("%s: NEAR app %s, dstack OS image %s, OS build pinned: %v\n\t{MRTD: %q, RTMR0: %q, RTMR1: %q, RTMR2: %q},",
		name, events["app-id"], events["os-image-hash"], tdx.CheckOS(m, pinned) == nil, os.MRTD, os.RTMR0, os.RTMR1, os.RTMR2)
}

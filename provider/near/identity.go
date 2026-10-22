package near

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	nearai "github.com/nearai/inference-sdk/go"
	"golang.org/x/sync/singleflight"

	"github.com/BOTChainLabs/private-ai-go/core"
	"github.com/BOTChainLabs/private-ai-go/internal/tdx"
)

const identityMaxAge = time.Hour

// osQuoteVerifier wraps a DCAP verifier so that every quote NEAR's SDK
// verifies must also come from an accepted dstack OS build.
func osQuoteVerifier(verify nearai.QuoteVerifier, allowed []tdx.OSMeasurement) nearai.QuoteVerifier {
	return func(ctx context.Context, hexQuote string) (nearai.QuoteVerificationResult, error) {
		r, err := verify(ctx, hexQuote)
		if err != nil {
			return r, err
		}
		m, err := tdx.ParseHexQuote(hexQuote)
		if err != nil {
			return nearai.QuoteVerificationResult{}, err
		}
		if !slices.Equal(m.RTMR3, r.RTMR3) || !slices.Equal(m.ReportData, r.ReportData) {
			return nearai.QuoteVerificationResult{}, fmt.Errorf("quote fields disagree with the DCAP verifier")
		}
		if err := tdx.CheckOS(m, allowed); err != nil {
			return nearai.QuoteVerificationResult{}, err
		}
		return r, nil
	}
}

// attestationSource fetches evidence; nearai.AttestationClient implements it.
type attestationSource interface {
	FetchGatewayAttestation(ctx context.Context, o nearai.FetchOptions) (nearai.FetchedGatewayAttestation, error)
	FetchModelAttestations(ctx context.Context, model string, o nearai.FetchOptions) (nearai.FetchedModelAttestations, error)
}

type (
	verifyGatewayFunc func(context.Context, nearai.Attestation, nearai.ClientBinding) (nearai.VerifiedAttestation, error)
	verifyModelFunc   func(context.Context, nearai.Attestation, nearai.ClientBinding) (nearai.VerifiedAttestation, error)
)

// established is what an identity check proved for one model: the gateway
// TLS keys and model signing keys that belong to NEAR's apps.
type established struct {
	gatewaySPKIs []string
	signers      []nearai.SigningIdentity
	modelAppID   string
	expires      time.Time
}

// identity proves which code serves a model, beyond NEAR's SDK: the dstack
// app and KMS read from the RTMR3 event log. The SDK's policy hooks do not
// expose the event log, so the gateway and model reports are fetched and
// fully verified here (quote, binding, event-log replay; the GPU is checked
// by the SDK's own preflight). The keys they establish are then required of
// the SDK's session before a prompt is sent, and of every response
// signature.
type identity struct {
	src           attestationSource
	verifyGateway verifyGatewayFunc
	verifyModel   verifyModelFunc
	workload      Workload
	now           func() time.Time

	once  singleflight.Group
	mu    sync.Mutex
	cache map[string]*established
}

func (id *identity) get(ctx context.Context, model string) (*established, error) {
	id.mu.Lock()
	e := id.cache[model]
	id.mu.Unlock()
	if e != nil && id.now().Before(e.expires) {
		return e, nil
	}
	ch := id.once.DoChan(model, func() (any, error) {
		ictx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		e, err := id.establish(ictx, model)
		if err != nil {
			return nil, err
		}
		id.mu.Lock()
		id.cache[model] = e
		id.mu.Unlock()
		return e, nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.Err != nil {
			return nil, r.Err
		}
		return r.Val.(*established), nil
	}
}

func (id *identity) establish(ctx context.Context, model string) (*established, error) {
	noCaller := context.Background()
	opts := nearai.FetchOptions{SigningAlgo: nearai.Ed25519}
	e := &established{expires: id.now().Add(identityMaxAge)}

	g, err := id.src.FetchGatewayAttestation(ctx, opts)
	if err != nil {
		return nil, core.Wrap(noCaller, codeFor(err), err, "fetch gateway attestation")
	}
	if err := precheckOS(g.Attestation, id.workload.OS); err != nil {
		return nil, core.Errorf(core.CodeAttestationFailed, err, "gateway")
	}
	vg, err := id.verifyGateway(ctx, g.Attestation, g.ClientBinding)
	if err != nil {
		return nil, core.Wrap(noCaller, codeFor(err), err, "verify gateway attestation")
	}
	if _, err := checkApp(g.Attestation, id.workload.OS, id.workload.Gateway); err != nil {
		return nil, core.Errorf(core.CodeAttestationFailed, err, "gateway is not NEAR's gateway app")
	}
	e.gatewaySPKIs = append(e.gatewaySPKIs, strings.ToLower(vg.SPKIFingerprint))

	m, err := id.src.FetchModelAttestations(ctx, model, opts)
	if err != nil {
		return nil, core.Wrap(noCaller, codeFor(err), err, "fetch model attestations")
	}
	if len(m.Attestations) == 0 {
		return nil, core.Errorf(core.CodeRouteNotTEE, nil, "model %s has no TEE attestation", model)
	}
	// Every instance must pass, as NEAR's SDK requires of its own reports.
	for _, a := range m.Attestations {
		if err := precheckOS(a, id.workload.OS); err != nil {
			return nil, core.Errorf(core.CodeAttestationFailed, err, "model %s instance %s", model, a.InstanceID)
		}
		vm, err := id.verifyModel(ctx, a, m.ClientBinding)
		if err != nil {
			return nil, core.Wrap(noCaller, codeFor(err), err, "verify model attestation")
		}
		appID, err := checkApp(a, id.workload.OS, id.workload.Model)
		if err != nil {
			return nil, core.Errorf(core.CodeAttestationFailed, err, "model %s instance %s is not a NEAR model app", model, a.InstanceID)
		}
		e.modelAppID = appID
		e.signers = append(e.signers, vm.Signer)
	}
	return e, nil
}

// precheckOS names an unknown OS build, which the SDK's verification would
// report only as a failed quote (an OS upgrade on NEAR's side looks like
// this). It decides nothing on its own: the quote is not verified yet, and
// the SDK's verification checks the OS again on the verified quote.
func precheckOS(a nearai.Attestation, os []tdx.OSMeasurement) error {
	m, err := tdx.ParseHexQuote(a.IntelQuote)
	if err != nil {
		return nil // reported by the SDK's verification
	}
	return tdx.CheckOS(m, os)
}

// checkApp checks the OS build and the dstack app identity of a report whose
// quote has been verified, and returns its app ID.
func checkApp(a nearai.Attestation, os []tdx.OSMeasurement, app tdx.App) (string, error) {
	m, err := tdx.ParseHexQuote(a.IntelQuote)
	if err != nil {
		return "", err
	}
	if err := tdx.CheckOS(m, os); err != nil {
		return "", err
	}
	events, err := tdx.ReplayRTMR3(a.EventLog, m.RTMR3)
	if err != nil {
		return "", err
	}
	return events["app-id"], app.Check(events)
}

func (e *established) hasSigner(s nearai.SigningIdentity) bool {
	return slices.ContainsFunc(e.signers, func(k nearai.SigningIdentity) bool {
		return k.SigningAlgo == s.SigningAlgo && strings.EqualFold(k.SigningAddress, s.SigningAddress)
	})
}

// checkSession requires the SDK's session for model, the one its next
// request is encrypted under, to use only identity-checked keys.
func (e *established) checkSession(r nearai.AttestationVerificationResult) error {
	if r.Gateway != nil && !slices.Contains(e.gatewaySPKIs, strings.ToLower(r.Gateway.SPKIFingerprint)) {
		return fmt.Errorf("gateway TLS key %s was not established as NEAR's gateway", r.Gateway.SPKIFingerprint)
	}
	if len(r.Models) == 0 {
		return fmt.Errorf("session has no attested model")
	}
	for _, m := range r.Models {
		if !e.hasSigner(m.Signer) {
			return fmt.Errorf("model signer %s was not established as a NEAR model app", m.Signer.SigningAddress)
		}
	}
	return nil
}

package near

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
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

// learnRounds bounds the extra attestation fetches made for a session whose
// keys are not established yet. NEAR serves a model from several machines
// and each fetch reports one of them, so the first fetch may have shown
// another machine than the one a session uses.
const learnRounds = 4

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
// TLS keys and model signing keys that belong to NEAR's apps, and the RTMR3
// of each machine that passed. It is not modified once published; merge
// returns a new one.
type established struct {
	gatewaySPKIs  []string
	apps          map[string]string // model signer (signerKey) -> its app ID
	gatewayRTMR3s []string          // hex
	modelRTMR3s   []string          // hex
	expires       time.Time
}

// errUnestablished refuses a quote from a machine the identity check has not
// established, or not within identityMaxAge.
var errUnestablished = errors.New("machine not established as a NEAR app")

// role is what a machine was established as.
type role int

const (
	roleGateway role = iota
	roleModel
)

// gate extends verify, which NEAR's SDK verifies its sessions' quotes with,
// to accept only machines this identity has established in r: a quote's
// RTMR3 must be one whose event log was replayed and passed the app, KMS
// and OS checks. RTMR3 commits to every RTMR3 event, the app-id and
// key-provider among them, so another app's or KMS's machine cannot have it.
func (id *identity) gate(verify nearai.QuoteVerifier, r role) nearai.QuoteVerifier {
	return func(ctx context.Context, hexQuote string) (nearai.QuoteVerificationResult, error) {
		q, err := verify(ctx, hexQuote)
		if err != nil {
			return q, err
		}
		if !id.knows(r, q.RTMR3) {
			return nearai.QuoteVerificationResult{}, fmt.Errorf("%w (RTMR3 %x)", errUnestablished, q.RTMR3)
		}
		return q, nil
	}
}

// knows reports whether an unexpired identity has established a machine
// with rtmr3 in r.
func (id *identity) knows(r role, rtmr3 []byte) bool {
	if len(rtmr3) != 48 {
		return false
	}
	h := hex.EncodeToString(rtmr3)
	id.mu.Lock()
	defer id.mu.Unlock()
	now := id.now()
	for _, e := range id.cache {
		if !now.Before(e.expires) {
			continue
		}
		list := e.modelRTMR3s
		if r == roleGateway {
			list = e.gatewayRTMR3s
		}
		if slices.Contains(list, h) {
			return true
		}
	}
	return false
}

func signerKey(s nearai.SigningIdentity) string {
	return strings.ToLower(string(s.SigningAlgo) + ":" + s.SigningAddress)
}

// identity proves which code serves a model, beyond NEAR's SDK: the dstack
// app and KMS read from the RTMR3 event log. The SDK's policy hooks do not
// expose the event log, so the gateway and model reports are fetched and
// fully verified here (quote, binding, event-log replay; the GPU is checked
// by the SDK's own preflight). The SDK then accepts, for any session it
// creates, only quotes from the machines established here (gate); their
// keys are required of the SDK's session before a prompt is sent, and of
// every response signature.
type identity struct {
	src           attestationSource
	verifyGateway verifyGatewayFunc
	verifyModel   verifyModelFunc
	workload      Workload
	now           func() time.Time

	// base bounds identity checks, which outlive the call that started
	// them; close cancels it.
	base  context.Context
	close context.CancelFunc

	once  singleflight.Group
	mu    sync.Mutex
	cache map[string]*established
}

func newIdentity(src attestationSource, verifyGateway verifyGatewayFunc, verifyModel verifyModelFunc, w Workload) *identity {
	base, cancel := context.WithCancel(context.Background())
	return &identity{
		src: src, verifyGateway: verifyGateway, verifyModel: verifyModel, workload: w,
		now: time.Now, base: base, close: cancel, cache: map[string]*established{},
	}
}

func (id *identity) get(ctx context.Context, model string) (*established, error) {
	if e := id.cached(model); e != nil {
		return e, nil
	}
	return id.refresh(ctx, model)
}

func (id *identity) cached(model string) *established {
	id.mu.Lock()
	defer id.mu.Unlock()
	if e := id.cache[model]; e != nil && id.now().Before(e.expires) {
		return e
	}
	return nil
}

// refresh establishes the model's identity once more and adds what it proves
// to the cached identity, which keeps its own expiry.
func (id *identity) refresh(ctx context.Context, model string) (*established, error) {
	ch := id.once.DoChan(model, func() (any, error) {
		ictx, cancel := context.WithTimeout(id.base, 2*time.Minute)
		defer cancel()
		e, err := id.establish(ictx, model)
		if err != nil {
			return nil, err
		}
		if old := id.cached(model); old != nil {
			e = old.merge(e)
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
	e := &established{apps: map[string]string{}, expires: id.now().Add(identityMaxAge)}

	g, err := id.src.FetchGatewayAttestation(ctx, opts)
	if err != nil {
		return nil, core.Wrap(noCaller, codeFor(err), detailed(err), "fetch gateway attestation")
	}
	if err := precheckOS(g.Attestation, id.workload.OS); err != nil {
		return nil, core.Errorf(core.CodeAttestationFailed, err, "gateway")
	}
	vg, err := id.verifyGateway(ctx, g.Attestation, g.ClientBinding)
	if err != nil {
		return nil, core.Wrap(noCaller, codeFor(err), detailed(err), "verify gateway attestation")
	}
	if _, err := checkApp(g.Attestation, id.workload.OS, id.workload.Gateway); err != nil {
		return nil, core.Errorf(core.CodeAttestationFailed, err, "gateway is not NEAR's gateway app")
	}
	e.gatewaySPKIs = append(e.gatewaySPKIs, strings.ToLower(vg.SPKIFingerprint))
	e.gatewayRTMR3s = append(e.gatewayRTMR3s, rtmr3Of(g.Attestation))

	m, err := id.src.FetchModelAttestations(ctx, model, opts)
	if err != nil {
		return nil, core.Wrap(noCaller, codeFor(err), detailed(err), "fetch model attestations")
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
			return nil, core.Wrap(noCaller, codeFor(err), detailed(err), "verify model attestation")
		}
		appID, err := checkApp(a, id.workload.OS, id.workload.Model)
		if err != nil {
			return nil, core.Errorf(core.CodeAttestationFailed, err, "model %s instance %s is not a NEAR model app", model, a.InstanceID)
		}
		e.apps[signerKey(vm.Signer)] = appID
		e.modelRTMR3s = append(e.modelRTMR3s, rtmr3Of(a))
	}
	return e, nil
}

// rtmr3Of is the hex RTMR3 of a report checkApp has accepted, which parsed
// the same quote. An empty result never matches (knows).
func rtmr3Of(a nearai.Attestation) string {
	m, err := tdx.ParseHexQuote(a.IntelQuote)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(m.RTMR3)
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

// merge returns e extended by the keys and machines of fresh, expiring
// with e.
func (e *established) merge(fresh *established) *established {
	m := &established{apps: maps.Clone(e.apps), expires: e.expires}
	maps.Copy(m.apps, fresh.apps)
	m.gatewaySPKIs = union(e.gatewaySPKIs, fresh.gatewaySPKIs)
	m.gatewayRTMR3s = union(e.gatewayRTMR3s, fresh.gatewayRTMR3s)
	m.modelRTMR3s = union(e.modelRTMR3s, fresh.modelRTMR3s)
	return m
}

func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, s := range b {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func (e *established) hasSigner(s nearai.SigningIdentity) bool {
	_, ok := e.apps[signerKey(s)]
	return ok
}

// appOf returns the app ID of an established model signer.
func (e *established) appOf(s nearai.SigningIdentity) string { return e.apps[signerKey(s)] }

// checkSession requires the SDK's session for model, the one its next
// request is encrypted under, to use only identity-checked keys.
func (e *established) checkSession(r nearai.AttestationVerificationResult) error {
	if r.Gateway == nil {
		return errors.New("session has no attested gateway")
	}
	if !slices.Contains(e.gatewaySPKIs, strings.ToLower(r.Gateway.SPKIFingerprint)) {
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

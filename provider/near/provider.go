// Package near calls NEAR AI Cloud's private (TEE) models through NEAR's
// official Go SDK. Before sending, that SDK attests the gateway and the
// model (Intel TDX, NVIDIA GPU, measured compose), pins the gateway's TLS
// key and encrypts the request to the attested model key; afterwards it
// verifies the response signature over the exact bytes.
//
// This package adds the SDK policy: E2EE always on, the deployment policy,
// a route check, and Verified only for a signature made by the attested
// model (provider_tee). A gateway signature proves only that the gateway
// relayed the bytes, and E2EE does not authenticate the response (it is
// encrypted with an unauthenticated ephemeral key), so it is not enough.
package near

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	nearai "github.com/nearai/inference-sdk/go"

	"github.com/BOTChainLabs/private-ai-go/core"
	"github.com/BOTChainLabs/private-ai-go/internal/oai"
)

// route names how a NEAR result is verified: a signature by the attested
// model over the exact request and response, with the request E2EE.
const route = "near-provider-tee"

type Options struct {
	APIKey  string
	BaseURL string // defaults to NEAR AI Cloud's gateway
	// Timeout bounds each call, including the verification.
	Timeout time.Duration
	Policy  core.Policy
	// Workload is the gateway and model code to accept. Nil means
	// ProductionWorkload, which matches NEAR AI Cloud.
	Workload *Workload
}

// client is the part of NEAR's SDK the adapter uses; tests substitute it.
type client interface {
	HTTPClient() *http.Client
	BaseURL() string
	Verify(ctx context.Context, model string) (nearai.AttestationVerificationResult, error)
	VerifyResponse(ctx context.Context, id string) (nearai.VerifiedCompletionResult, error)
	Close() error
}

type Provider struct {
	c       client
	ident   *identity
	chatURL string
	timeout time.Duration
}

// New creates the provider. E2EE is always on, so NEAR's SDK refuses before
// sending any model without a verified TEE key (the Incognito and
// third-party routes).
func New(o Options) (*Provider, error) {
	if o.APIKey == "" {
		return nil, errors.New("near: API key is required")
	}
	w := ProductionWorkload()
	if o.Workload != nil {
		w = *o.Workload
	}
	quote := osQuoteVerifier(nearai.CreateTDXQuoteVerifier(""), w.OS)
	tcb := o.Policy.TCBStatuses()
	gateway := nearai.VerificationOptions{Policy: nearai.AttestationPolicy{AcceptedTCBStatuses: tcb}, QuoteVerifier: quote}
	// Model VMs run on confidential GPUs: their NVIDIA evidence must be
	// present and verified, not only checked when supplied.
	model := gateway
	model.Policy.RequireGPUEvidence = true

	clientOpts := nearai.ClientOptions{APIKey: o.APIKey, BaseURL: o.BaseURL}
	c, err := nearai.NewInferenceClient(nearai.InferenceOptions{
		ClientOptions:       clientOpts,
		SigningAlgo:         nearai.Ed25519,
		E2EE:                true,
		GatewayVerification: gateway,
		ModelVerification:   model,
		DeploymentPolicy:    deploymentPolicy(o.Policy),
	})
	if err != nil {
		return nil, fmt.Errorf("near: %w", err)
	}
	src, err := nearai.NewAttestationClient(clientOpts)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("near: %w", err)
	}
	// The identity check reads which app runs. The GPU evidence of the
	// keys it establishes is verified by the session preflight above.
	identityOpts := gateway
	identityOpts.GPUVerifier = func(context.Context, string) error { return nil }
	ident := &identity{
		src: src,
		verifyGateway: func(ctx context.Context, a nearai.Attestation, b nearai.ClientBinding) (nearai.VerifiedAttestation, error) {
			return nearai.VerifyGatewayAttestation(ctx, a, b, identityOpts)
		},
		verifyModel: func(ctx context.Context, a nearai.Attestation, b nearai.ClientBinding) (nearai.VerifiedAttestation, error) {
			return nearai.VerifyModelAttestation(ctx, a, b, identityOpts)
		},
		workload: w,
		now:      time.Now,
		cache:    map[string]*established{},
	}
	return newWithClient(c, ident, o.Timeout)
}

// deploymentPolicy enforces the compose allowlist, when one is set, on the
// model deployments NEAR's SDK admits.
func deploymentPolicy(p core.Policy) func(context.Context, string, nearai.MeasuredDeployment) error {
	if len(p.ComposeHashes) == 0 {
		return nil
	}
	return func(_ context.Context, model string, d nearai.MeasuredDeployment) error {
		if !slices.Contains(p.ComposeHashes, strings.ToLower(d.RuntimeMeasurements.ComposeHash)) {
			return fmt.Errorf("model %s runs compose %s, which the policy does not allow", model, d.RuntimeMeasurements.ComposeHash)
		}
		return nil
	}
}

func newWithClient(c client, ident *identity, timeout time.Duration) (*Provider, error) {
	chatURL, err := url.JoinPath(c.BaseURL(), "chat/completions")
	if err != nil {
		return nil, fmt.Errorf("near: %w", err)
	}
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	return &Provider{c: c, ident: ident, chatURL: chatURL, timeout: timeout}, nil
}

func (p *Provider) ID() core.ProviderID { return core.NEAR }

// Close cancels NEAR's shared verification work and releases connections.
func (p *Provider) Close() error { return p.c.Close() }

// Infer sends one chat completion and returns it only when the attested
// model's signature over the exact bytes verifies.
func (p *Provider) Infer(ctx context.Context, req core.InferRequest) (*core.InferResult, error) {
	callCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	e, err := p.checkIdentity(callCtx, ctx, req.Model)
	if err != nil {
		return nil, err
	}
	resp, err := p.send(callCtx, ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// NEAR's SDK has already bounded and decrypted this body.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, core.Wrap(ctx, codeFor(err), err, "read inference response")
	}
	c, err := oai.ParseCompletion(body)
	if err != nil {
		return nil, err
	}
	ver, err := p.verify(callCtx, ctx, c.ID, req.Model, e)
	if err != nil {
		return nil, err
	}
	return &core.InferResult{Content: c.Content, Raw: body, Usage: c.Usage, Verification: ver}, nil
}

// checkIdentity establishes which code serves model and requires the SDK's
// session, the one the prompt will be encrypted under, to use only those
// keys. It runs before anything is sent.
func (p *Provider) checkIdentity(ctx, callerCtx context.Context, model string) (*established, error) {
	e, err := p.ident.get(ctx, model)
	if err != nil {
		if callerCtx.Err() != nil {
			return nil, callerCtx.Err()
		}
		return nil, err
	}
	sess, err := p.c.Verify(ctx, model)
	if err != nil {
		return nil, core.Wrap(callerCtx, codeFor(err), err, "attest NEAR session")
	}
	if e, err = p.ident.covering(ctx, model, e, sess); err != nil {
		if callerCtx.Err() != nil {
			return nil, callerCtx.Err()
		}
		return nil, err
	}
	return e, nil
}

// send posts the request through NEAR's verified transport and checks the
// status and serving route. callerCtx tells the caller's cancellation apart
// from the call timeout. On success the caller owns resp.Body.
func (p *Provider) send(ctx, callerCtx context.Context, req core.InferRequest) (*http.Response, error) {
	body, err := json.Marshal(oai.Body(req, false))
	if err != nil {
		return nil, core.Errorf(core.CodeInvalidRequest, err, "encode request")
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.chatURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := p.c.HTTPClient().Do(hreq)
	if err != nil {
		return nil, core.Wrap(callerCtx, codeFor(err), err, "inference request")
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, core.Errorf(core.CodeProviderError, nil, "HTTP %d: %s", resp.StatusCode, truncate(b, 300))
	}
	// The header is a hint, not proof (the model signature is the proof),
	// but a gateway that says it served elsewhere is believed.
	if sp := resp.Header.Get("X-Serving-Provider"); sp != "" && !strings.EqualFold(sp, "near") {
		resp.Body.Close()
		return nil, core.Errorf(core.CodeRouteNotTEE, nil, "served by %q, not a NEAR private TEE", sp)
	}
	return resp, nil
}

// verify checks the response signature for a completed exchange. Only a
// provider_tee signature, made by the attested model over the exact request
// and response bytes, makes the result Verified.
func (p *Provider) verify(ctx, callerCtx context.Context, id, model string, e *established) (core.Verification, error) {
	ver := core.Verification{Status: core.Unverified, Provider: core.NEAR, Model: model, Route: route}
	fail := func(status core.Status, err *core.Error) (core.Verification, error) {
		ver.Status = status
		ver.Reasons = []string{err.Cause.Error()}
		v := ver
		err.Verification = &v
		return ver, err
	}
	if id == "" {
		return fail(core.Unverified, core.Errorf(core.CodeEvidenceUnavailable, errors.New("response has no completion id"), "verify response"))
	}
	ver.Evidence.ReceiptID = id

	r, err := p.c.VerifyResponse(ctx, id)
	if err != nil {
		if callerCtx.Err() != nil {
			return ver, err
		}
		ce := core.Errorf(codeFor(err), err, "verify response")
		status := core.Failed
		if ce.Code == core.CodeEvidenceUnavailable || ce.Code == core.CodeVerifierUnavailable {
			status = core.Unverified
		}
		return fail(status, ce)
	}
	switch r.SignatureKind {
	case "provider_tee":
	case "gateway":
		return fail(core.Unverified, core.Errorf(core.CodeRouteNotTEE, errors.New("response is signed by the gateway only; model execution in a TEE is not proven"), "verify response"))
	default:
		return fail(core.Failed, core.Errorf(core.CodeReceiptInvalid, fmt.Errorf("unknown signature kind %q", r.SignatureKind), "verify response"))
	}

	if r.Attestation == nil || !e.hasSigner(r.Attestation.Signer) {
		return fail(core.Failed, core.Errorf(core.CodeAttestationFailed, errors.New("response signer was not established as a NEAR model app"), "verify response"))
	}

	ver.Status = core.Verified
	ver.Evidence.AppID = e.modelAppID
	if sig, err := json.Marshal(r.Signature); err == nil {
		ver.Evidence.Receipt = sig
	}
	if a := r.Attestation; a != nil {
		ver.Evidence.TCBStatus = a.TCBStatus
		ver.Evidence.ComposeHash = a.Deployment.RuntimeMeasurements.ComposeHash
		ver.Evidence.OSImageHash = a.Deployment.RuntimeMeasurements.OSImageHash
	}
	return ver, nil
}

func codeFor(err error) string {
	var ne *nearai.Error
	if !errors.As(err, &ne) {
		return core.CodeProviderError
	}
	c := ne.Code
	switch {
	case c == "policy.model_attestation_required", c == "e2ee.model_public_key_required", c == "api.model_attestation_not_found":
		return core.CodeRouteNotTEE
	case strings.HasPrefix(c, "binding.spki"):
		return core.CodeTLSPinMismatch
	case c == "api.completion_signature_unavailable", c == "api.completion_not_found":
		return core.CodeEvidenceUnavailable
	// The external verifiers (Intel collateral, NVIDIA NRAS) could not be
	// reached or refused the request: nothing was proven wrong.
	case c == "gpu.nras_request_failed", c == "quote.collateral_unavailable",
		ne.Retryable && (strings.HasPrefix(c, "quote.") || strings.HasPrefix(c, "gpu.")):
		return core.CodeVerifierUnavailable
	case strings.HasPrefix(c, "signature."), c == "e2ee.decryption_failed":
		return core.CodeReceiptInvalid
	case hasPrefix(c, "quote.", "binding.", "measurement.", "policy.", "gpu.", "provenance.", "e2ee."):
		return core.CodeAttestationFailed
	case c == "api.invalid_input":
		return core.CodeInvalidRequest
	default:
		return core.CodeProviderError
	}
}

func hasPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}

package privateai

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/BOTChainLabs/private-ai-go/core"
	"github.com/BOTChainLabs/private-ai-go/internal/tdx"
	"github.com/BOTChainLabs/private-ai-go/provider/near"
	"github.com/BOTChainLabs/private-ai-go/provider/phala"
)

type (
	ProviderID   = core.ProviderID
	Message      = core.Message
	InferRequest = core.InferRequest
	InferResult  = core.InferResult
	Chunk        = core.Chunk
	Verification = core.Verification
	Evidence     = core.Evidence
	Usage        = core.Usage
	Status       = core.Status
	ModelEntry   = core.ModelEntry
	Policy       = core.Policy
	Error        = core.Error

	// OSMeasurement is a dstack OS build, by its boot measurements MRTD and
	// RTMR0-2 (hex).
	OSMeasurement = tdx.OSMeasurement
)

const (
	Phala = core.Phala
	NEAR  = core.NEAR
	// Gateway is a self-hosted Private AI Gateway, the open-source gateway
	// Phala runs, deployed by someone else (for example the BotChain AI
	// Gateway). It has no built-in identity: ProviderConfig.BaseURL and
	// ProviderConfig.Identity are required, and E2EE is always on.
	Gateway = core.Gateway

	Verified   = core.Verified
	Failed     = core.Failed
	Unverified = core.Unverified
)

// Error codes; see core for their meaning.
const (
	CodeInvalidRequest      = core.CodeInvalidRequest
	CodeModelNotAllowed     = core.CodeModelNotAllowed
	CodeAttestationFailed   = core.CodeAttestationFailed
	CodeTLSPinMismatch      = core.CodeTLSPinMismatch
	CodeReceiptInvalid      = core.CodeReceiptInvalid
	CodeRouteNotTEE         = core.CodeRouteNotTEE
	CodeEvidenceUnavailable = core.CodeEvidenceUnavailable
	CodeVerifierUnavailable = core.CodeVerifierUnavailable
	CodeProviderError       = core.CodeProviderError
)

// ProviderConfig configures one provider. The API key is the developer's
// own (BYOK): the provider bills that account directly.
type ProviderConfig struct {
	APIKey string
	// BaseURL is the gateway's https URL: required for Gateway, optional
	// for Phala and NEAR (testing). Any other scheme is refused.
	BaseURL string
	// Policy tightens which attested deployments are accepted. The zero
	// value accepts the TCB statuses UpToDate and OutOfDate and any compose
	// the provider's built-in identity checks allow.
	Policy Policy

	// E2EE also encrypts message content to Phala's attested gateway, and
	// the answer back to this client (E2EE v2), on top of the pinned TLS
	// channel. Gateway always encrypts; NEAR always uses its own E2EE.
	E2EE bool

	// Identity is the deployment a Gateway provider must be running.
	// Required for Gateway, not allowed for Phala and NEAR, whose
	// identities are built in.
	Identity *GatewayIdentity

	// ExtraOSBuilds and ExtraAppIDs add to the provider's built-in identity
	// what this SDK version does not know yet: a provider OS upgrade, or a
	// NEAR AI model served as its own app (ExtraAppIDs extends NEAR's model
	// apps and Phala's gateway app). For Phala, each built-in deployment
	// keeps its own KMS: an extra OS build may run any of them, and an extra
	// app is accepted with the KMS and OS builds of any of them. For a
	// Gateway they extend Identity. Verification refuses an unknown build or
	// app and names it in the error; add it here only once the provider has
	// confirmed it.
	ExtraOSBuilds []OSMeasurement
	ExtraAppIDs   []string
}

// GatewayIdentity pins a self-hosted Private AI Gateway, deployed as a
// dstack app. The operator publishes these values; verification errors also
// print the observed ones. Values are hex.
type GatewayIdentity struct {
	// AppIDs are the gateway's dstack app IDs (40 hex characters).
	// Required.
	AppIDs []string
	// OS lists the dstack OS builds the gateway may boot. Required.
	OS []OSMeasurement
	// KeyProviders identify the KMS that releases the app's keys, as the
	// key-provider event's payload. Empty means Phala Cloud's KMS, the one
	// Phala's own gateway uses.
	KeyProviders []string
	// KMSMeasurements optionally pin the KMS build (the mr-kms event).
	KMSMeasurements []string
	// ComposeHashes pin the gateway's releases: the SHA-256 of the
	// app-compose of each release the operator publishes. Required: the
	// operator can authorise a new compose for its app at any time, and the
	// app ID, OS and KMS alone would accept it, whatever it does with
	// plaintext.
	ComposeHashes []string
	// AllowTLSOutsideTEE accepts a gateway whose TLS ends outside its TEE,
	// such as behind Phala Cloud's ingress, so that its keyset lists no TLS
	// key. E2EE then keeps message content from the gateway's operator, but
	// not from whoever terminates TLS: E2EE v2 does not bind the client's
	// key, so that party can resend a request with its own key within the
	// replay window and read the answer. Leave it false unless you trust the
	// TLS terminator; a gateway that terminates TLS inside its TEE needs no
	// such trust. The serving mode the gateway reports is outside its
	// attestation and is then ignored: every receipt must show a verified
	// upstream TEE session, so a gateway in direct mode is refused.
	AllowTLSOutsideTEE bool
}

// Config lists the providers to enable and the models the client may call.
type Config struct {
	Providers map[ProviderID]ProviderConfig
	// Models lists the only models the client may call.
	Models []ModelEntry
	// Timeout bounds each non-streaming call as a whole, including its
	// attestation and verification. For a stream it bounds opening it, until
	// the provider starts answering, and Stream.Verify; reading the stream
	// is bounded only by the caller's context, since an answer can take long
	// to generate. A NEAR stream is one verified non-streaming call, bounded
	// as a whole. Zero means 2 minutes.
	Timeout time.Duration
}

// Client calls the configured providers and returns only verified results.
// It is safe for concurrent use.
type Client struct {
	providers map[ProviderID]core.Provider
	models    []ModelEntry
	allowed   map[ModelEntry]bool
}

// New validates cfg and creates the providers. No network call is made
// until the first inference.
func New(cfg Config) (*Client, error) {
	c := &Client{providers: map[ProviderID]core.Provider{}, allowed: map[ModelEntry]bool{}}
	if err := c.init(cfg); err != nil {
		c.Close() // release providers created before the failure
		return nil, err
	}
	return c, nil
}

func (c *Client) init(cfg Config) error {
	if cfg.Timeout < 0 {
		return errors.New("privateai: Timeout must not be negative")
	}
	for id, pc := range cfg.Providers {
		p, err := newProvider(id, pc, cfg.Timeout)
		if err != nil {
			return err
		}
		c.providers[id] = p
	}
	for _, m := range cfg.Models {
		if m.Model == "" {
			return fmt.Errorf("privateai: a model for %q has no name", m.Provider)
		}
		if _, ok := c.providers[m.Provider]; !ok {
			return fmt.Errorf("privateai: model %s is listed for unconfigured provider %q", m.Model, m.Provider)
		}
		if !c.allowed[m] {
			c.models = append(c.models, m)
			c.allowed[m] = true
		}
	}
	if len(c.models) == 0 {
		return errors.New("privateai: no models configured")
	}
	return nil
}

func newProvider(id ProviderID, pc ProviderConfig, timeout time.Duration) (core.Provider, error) {
	if err := pc.checkExtras(); err != nil {
		return nil, fmt.Errorf("privateai: %s: %w", id, err)
	}
	if pc.Identity != nil && id != Gateway {
		return nil, fmt.Errorf("privateai: %s: Identity is only for the Gateway provider", id)
	}
	switch id {
	case Phala:
		return phala.New(phalaOptions(pc, timeout))
	case NEAR:
		return near.New(nearOptions(pc, timeout))
	case Gateway:
		o, err := gatewayOptions(pc, timeout)
		if err != nil {
			return nil, fmt.Errorf("privateai: %s: %w", id, err)
		}
		return phala.New(o)
	default:
		return nil, fmt.Errorf("privateai: unknown provider %q", id)
	}
}

func phalaOptions(pc ProviderConfig, timeout time.Duration) phala.Options {
	w := phala.ProductionWorkload()
	w.OS = append(w.OS, pc.ExtraOSBuilds...)
	w.AppIDs = append(w.AppIDs, pc.ExtraAppIDs...)
	// Phala's deployments stay bound to their own KMS: an extra OS build may
	// run either deployment, and an extra app may take the place of either
	// deployment's app, with that deployment's KMS and OS builds.
	for i, d := range w.Deployments {
		w.Deployments[i].OS = append(slices.Clip(d.OS), pc.ExtraOSBuilds...)
		w.Deployments[i].AppIDs = append(slices.Clip(d.AppIDs), pc.ExtraAppIDs...)
	}
	return phala.Options{APIKey: pc.APIKey, BaseURL: pc.BaseURL, Timeout: timeout, Policy: pc.Policy, Workload: &w, E2EE: pc.E2EE}
}

// gatewayOptions verifies a self-hosted gateway with Phala's ACI provider,
// against the deployment's own identity and always with E2EE.
func gatewayOptions(pc ProviderConfig, timeout time.Duration) (phala.Options, error) {
	g := pc.Identity
	if g == nil {
		return phala.Options{}, errors.New("Identity is required: the gateway has no built-in identity")
	}
	if pc.BaseURL == "" {
		return phala.Options{}, errors.New("BaseURL is required")
	}
	if len(g.AppIDs) == 0 || len(g.OS) == 0 || len(g.ComposeHashes) == 0 {
		return phala.Options{}, errors.New("Identity needs the gateway's AppIDs, OS builds and ComposeHashes")
	}
	for i, h := range g.ComposeHashes {
		if b, err := hex.DecodeString(h); err != nil || len(b) != 32 {
			return phala.Options{}, fmt.Errorf("Identity.ComposeHashes[%d] is not a SHA-256 in hex", i)
		}
	}
	if len(pc.Policy.ComposeHashes) > 0 {
		return phala.Options{}, errors.New("set the gateway's compose hashes in Identity.ComposeHashes, not Policy")
	}
	if err := checkIdentity(g.OS, "Identity.OS", g.AppIDs, "Identity.AppIDs"); err != nil {
		return phala.Options{}, err
	}
	for name, list := range map[string][]string{"KeyProviders": g.KeyProviders, "KMSMeasurements": g.KMSMeasurements} {
		for i, v := range list {
			if b, err := hex.DecodeString(v); err != nil || len(b) == 0 {
				return phala.Options{}, fmt.Errorf("Identity.%s[%d] is not hex", name, i)
			}
		}
	}
	w := phala.Workload{
		OS:              append(slices.Clone(g.OS), pc.ExtraOSBuilds...),
		AppIDs:          append(slices.Clone(g.AppIDs), pc.ExtraAppIDs...),
		KeyProviders:    slices.Clone(g.KeyProviders),
		KMSMeasurements: slices.Clone(g.KMSMeasurements),
	}
	if len(w.KeyProviders) == 0 {
		w.KeyProviders = phala.CloudKeyProviders()
	}
	policy := pc.Policy
	policy.ComposeHashes = slices.Clone(g.ComposeHashes)
	return phala.Options{
		ID: Gateway, APIKey: pc.APIKey, BaseURL: pc.BaseURL, Timeout: timeout,
		Policy: policy, Workload: &w, E2EE: true, UnpinnedTLS: g.AllowTLSOutsideTEE,
	}, nil
}

func nearOptions(pc ProviderConfig, timeout time.Duration) near.Options {
	w := near.ProductionWorkload()
	w.OS = append(w.OS, pc.ExtraOSBuilds...)
	w.Model.AppIDs = append(w.Model.AppIDs, pc.ExtraAppIDs...)
	return near.Options{APIKey: pc.APIKey, BaseURL: pc.BaseURL, Timeout: timeout, Policy: pc.Policy, Workload: &w}
}

// checkExtras rejects malformed identity values, which would otherwise
// never match and fail every call with a misleading error.
func (pc ProviderConfig) checkExtras() error {
	return checkIdentity(pc.ExtraOSBuilds, "ExtraOSBuilds", pc.ExtraAppIDs, "ExtraAppIDs")
}

func checkIdentity(builds []OSMeasurement, osName string, appIDs []string, appName string) error {
	for i, b := range builds {
		for _, f := range []struct{ name, v string }{{"MRTD", b.MRTD}, {"RTMR0", b.RTMR0}, {"RTMR1", b.RTMR1}, {"RTMR2", b.RTMR2}} {
			if !isHex(f.v, 48) {
				return fmt.Errorf("%s[%d].%s must be 96 hex characters", osName, i, f.name)
			}
		}
	}
	for i, a := range appIDs {
		if !isHex(a, 20) {
			return fmt.Errorf("%s[%d] must be 40 hex characters", appName, i)
		}
	}
	return nil
}

func isHex(s string, n int) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == n
}

// Close releases every provider's connections and background work. The
// client must not be used afterwards.
func (c *Client) Close() error {
	var errs []error
	for _, p := range c.providers {
		if err := p.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ListModels returns the models this client is allowed to call.
func (c *Client) ListModels() []ModelEntry {
	return append([]ModelEntry(nil), c.models...)
}

// Infer runs one non-streaming inference. A nil error means the result is
// Verified.
func (c *Client) Infer(ctx context.Context, req InferRequest) (*InferResult, error) {
	p, err := c.provider(req)
	if err != nil {
		return nil, err
	}
	res, err := p.Infer(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := requireVerified(&res.Verification); err != nil {
		return nil, err
	}
	return res, nil
}

// Stream starts a streaming inference. Content from Recv is unverified until
// the stream has been read to io.EOF and Verify has returned a nil error.
func (c *Client) Stream(ctx context.Context, req InferRequest) (*Stream, error) {
	p, err := c.provider(req)
	if err != nil {
		return nil, err
	}
	ps, err := p.Stream(ctx, req)
	if err != nil {
		return nil, err
	}
	return &Stream{ps: ps}, nil
}

// provider validates a request and returns the provider allowed to serve it.
func (c *Client) provider(req InferRequest) (core.Provider, error) {
	if len(req.Messages) == 0 {
		return nil, core.Errorf(core.CodeInvalidRequest, nil, "messages must not be empty")
	}
	if !c.allowed[ModelEntry{Provider: req.Provider, Model: req.Model}] {
		return nil, core.Errorf(core.CodeModelNotAllowed, nil, "%s/%s is not in the model list", req.Provider, req.Model)
	}
	return c.providers[req.Provider], nil
}

// requireVerified is defense in depth: never hand back anything that is not
// Verified, whatever a provider returned.
func requireVerified(v *Verification) error {
	if v.Status == Verified {
		return nil
	}
	cp := *v
	return &core.Error{Code: core.CodeReceiptInvalid, Message: "provider returned an unverified result", Verification: &cp}
}

// Stream is a streaming inference. It is not safe for concurrent use.
type Stream struct {
	ps core.ProviderStream
}

// Recv returns the next delta, or io.EOF once the stream is complete.
func (s *Stream) Recv() (Chunk, error) { return s.ps.Recv() }

// Verify checks the complete stream. A nil error means everything received
// is Verified.
func (s *Stream) Verify(ctx context.Context) (*Verification, error) {
	v, err := s.ps.Verify(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireVerified(v); err != nil {
		return nil, err
	}
	return v, nil
}

// Usage is the token usage reported at the end of the stream.
func (s *Stream) Usage() Usage { return s.ps.Usage() }

// Close releases the connection. A stream closed before io.EOF cannot be
// verified.
func (s *Stream) Close() error { return s.ps.Close() }

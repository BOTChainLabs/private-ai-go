package privateai

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/BOTChainLabs/private-ai-go/core"
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
)

const (
	Phala = core.Phala
	NEAR  = core.NEAR

	Verified   = core.Verified
	Failed     = core.Failed
	Unverified = core.Unverified
)

type ProviderConfig struct {
	APIKey  string
	BaseURL string // optional, for testing
	// Policy tightens which attested deployments are accepted. The zero
	// value accepts the TCB statuses UpToDate and OutOfDate and any compose
	// the provider's built-in identity checks allow.
	Policy Policy
}

type Config struct {
	Providers map[ProviderID]ProviderConfig
	// Models lists the only models the client may call.
	Models  []ModelEntry
	Timeout time.Duration
}

type Client struct {
	providers map[ProviderID]core.Provider
	models    []ModelEntry
	allowed   map[ModelEntry]bool
}

func New(cfg Config) (*Client, error) {
	c := &Client{providers: map[ProviderID]core.Provider{}, allowed: map[ModelEntry]bool{}}
	if err := c.init(cfg); err != nil {
		c.Close() // release providers created before the failure
		return nil, err
	}
	return c, nil
}

func (c *Client) init(cfg Config) error {
	for id, pc := range cfg.Providers {
		p, err := newProvider(id, pc, cfg.Timeout)
		if err != nil {
			return err
		}
		c.providers[id] = p
	}
	for _, m := range cfg.Models {
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
	switch id {
	case Phala:
		return phala.New(phala.Options{APIKey: pc.APIKey, BaseURL: pc.BaseURL, Timeout: timeout, Policy: pc.Policy})
	case NEAR:
		return near.New(near.Options{APIKey: pc.APIKey, BaseURL: pc.BaseURL, Timeout: timeout, Policy: pc.Policy})
	default:
		return nil, fmt.Errorf("privateai: unknown provider %q", id)
	}
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

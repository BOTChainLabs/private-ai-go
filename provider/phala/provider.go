package phala

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	nearai "github.com/nearai/inference-sdk/go"
	"golang.org/x/sync/singleflight"

	"github.com/BOTChainLabs/private-ai-go/core"
)

const (
	DefaultBaseURL = "https://inference.phala.com"
	identityMaxAge = time.Hour
	maxBodyBytes   = 32 << 20
	// attestTries bounds the preflights spent looking for a keyset a receipt
	// names, when the deployment runs replicas with their own keysets.
	attestTries = 3
)

type Options struct {
	// ID names the gateway in results. Zero means core.Phala. Any other ID
	// is a gateway of its own, such as core.Gateway, and requires BaseURL
	// and Workload.
	ID      core.ProviderID
	APIKey  string
	BaseURL string // defaults to DefaultBaseURL for Phala
	// Timeout bounds non-streaming calls and the preflight. Streams are
	// bounded only by the caller's context.
	Timeout time.Duration
	// Workload is the gateway code to accept. Nil means ProductionWorkload,
	// which matches inference.phala.com.
	Workload *Workload
	Policy   core.Policy
	// E2EE encrypts message content to the gateway's attested key (E2EE v2)
	// and decrypts the generated content, on top of the pinned TLS channel.
	E2EE bool
	// UnpinnedTLS, with E2EE, accepts a gateway whose TLS ends outside its
	// TEE, such as at a cloud load balancer: its keyset lists no TLS key for
	// the host, and the attested E2EE key binds the channel instead. The API
	// key and the other parameters are then protected by ordinary TLS only.
	UnpinnedTLS bool
	// QuoteVerifier defaults to DefaultQuoteVerifier.
	QuoteVerifier QuoteVerifier
	// Transport is the base transport; tests inject one. Defaults to a clone
	// of http.DefaultTransport. It must use normal TLS verification.
	Transport *http.Transport
	Now       func() time.Time
}

// session is an established identity plus HTTP clients pinned to it.
type session struct {
	id           *Identity
	transport    *http.Transport
	client       *http.Client // with Options.Timeout
	streamClient *http.Client // no overall timeout; streams can be long
	expires      time.Time
}

type Provider struct {
	id           core.ProviderID
	route        string // how results were served, for Verification.Route
	e2ee         bool
	apiKey       string
	base         *url.URL
	timeout      time.Duration
	verifier     Verifier
	transport    *http.Transport
	attestClient *http.Client
	now          func() time.Time

	attestOnce singleflight.Group

	mu      sync.Mutex
	closed  bool
	current *session            // used for new requests
	known   map[string]*session // every unexpired verified keyset, by digest
}

func New(o Options) (*Provider, error) {
	id := o.ID
	if id == "" {
		id = core.Phala
	}
	if o.APIKey == "" {
		return nil, fmt.Errorf("%s: API key is required", id)
	}
	raw := o.BaseURL
	if raw == "" && id == core.Phala {
		raw = DefaultBaseURL
	}
	base, err := url.Parse(raw)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, fmt.Errorf("%s: base URL must be https: %q", id, raw)
	}
	// Phala's identity proves nothing about another gateway, and an empty
	// one would accept any app on any OS.
	if w := o.Workload; id != core.Phala && (w == nil || len(w.OS) == 0 || len(w.AppIDs) == 0 || len(w.KeyProviders) == 0) {
		return nil, fmt.Errorf("%s: the gateway's OS builds, app IDs and key providers are required", id)
	}
	if o.UnpinnedTLS && !o.E2EE {
		return nil, fmt.Errorf("%s: UnpinnedTLS requires E2EE", id)
	}
	p := &Provider{
		id:        id,
		route:     string(id) + "-aci",
		e2ee:      o.E2EE,
		apiKey:    o.APIKey,
		base:      base,
		timeout:   o.Timeout,
		transport: o.Transport,
		now:       o.Now,
		known:     map[string]*session{},
		verifier:  Verifier{Quote: o.QuoteVerifier, Policy: o.Policy, E2EE: o.E2EE, UnpinnedTLS: o.UnpinnedTLS},
	}
	if p.timeout == 0 {
		p.timeout = 2 * time.Minute
	}
	if p.verifier.Quote == nil {
		p.verifier.Quote = DefaultQuoteVerifier()
	}
	if o.Workload != nil {
		p.verifier.Workload = *o.Workload
	} else {
		p.verifier.Workload = ProductionWorkload()
	}
	if p.transport == nil {
		p.transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	if err := checkTransport(p.transport); err != nil {
		return nil, err
	}
	if p.now == nil {
		p.now = time.Now
	}
	p.attestClient = newClient(p.transport, p.timeout)
	return p, nil
}

func (p *Provider) ID() core.ProviderID { return p.id }

func (p *Provider) errClosed() error {
	return core.Errorf(core.CodeProviderError, nil, "%s provider is closed", p.id)
}

// Close drops every established session and its idle connections. A
// preflight still running when Close is called is discarded.
func (p *Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for d, s := range p.known {
		s.transport.CloseIdleConnections()
		delete(p.known, d)
	}
	p.current = nil
	p.transport.CloseIdleConnections()
	return nil
}

// Attest returns the current verified identity, running the preflight when
// there is none or it has expired.
func (p *Provider) Attest(ctx context.Context) (*Identity, error) {
	s, err := p.session(ctx)
	if err != nil {
		return nil, err
	}
	return s.id, nil
}

func (p *Provider) session(ctx context.Context) (*session, error) {
	p.mu.Lock()
	closed, s := p.closed, p.current
	p.mu.Unlock()
	if closed {
		return nil, p.errClosed()
	}
	if s != nil && p.now().Before(s.expires) {
		return s, nil
	}
	return p.refresh(ctx)
}

// refresh runs one preflight shared by all waiting callers. The preflight is
// detached from the first caller's cancellation so one impatient caller does
// not fail the others; every caller still stops waiting when its own context
// ends.
func (p *Provider) refresh(ctx context.Context) (*session, error) {
	ch := p.attestOnce.DoChan("attest", func() (any, error) {
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.timeout)
		defer cancel()
		return p.attest(actx)
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.Err != nil {
			return nil, r.Err
		}
		return r.Val.(*session), nil
	}
}

// sessionFor returns an established session for the keyset a receipt names.
// A deployment may run replicas with their own keysets (spec §3.3), so a
// keyset not seen yet is looked for with a few fresh preflights. Sessions
// other callers are using stay valid meanwhile.
func (p *Provider) sessionFor(ctx context.Context, digest string) (*session, error) {
	p.mu.Lock()
	s := p.known[digest]
	p.mu.Unlock()
	if s != nil && p.now().Before(s.id.NotAfter) {
		return s, nil
	}
	for range attestTries {
		s, err := p.refresh(ctx)
		if err != nil {
			return nil, err
		}
		if s.id.KeysetDigest == digest {
			return s, nil
		}
	}
	return nil, fmt.Errorf("receipt names keyset %s, which %d fresh attestations did not establish", digest, attestTries)
}

// invalidate makes the next request run a fresh preflight before sending.
func (p *Provider) invalidate() {
	p.mu.Lock()
	p.current = nil
	p.mu.Unlock()
}

// attest runs one preflight. It is detached from any caller, so every
// failure, including its own timeout, is reported as an SDK error.
func (p *Provider) attest(ctx context.Context) (*session, error) {
	noCaller := context.Background()
	nb := make([]byte, 32)
	if _, err := rand.Read(nb); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(nb)

	u := p.base.JoinPath("/v1/aci/attestation")
	u.RawQuery = url.Values{"nonce": {nonce}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := p.attestClient.Do(req)
	if err != nil {
		return nil, core.Wrap(noCaller, core.CodeEvidenceUnavailable, err, "fetch attestation report")
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body)
	if err != nil {
		return nil, core.Wrap(noCaller, core.CodeEvidenceUnavailable, err, "read attestation report")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, core.Errorf(core.CodeEvidenceUnavailable, nil, "attestation report: HTTP %d", resp.StatusCode)
	}
	var rep Report
	if err := json.Unmarshal(body, &rep); err != nil {
		return nil, core.Errorf(core.CodeAttestationFailed, err, "parse attestation report")
	}

	id, err := p.verifier.VerifyReport(ctx, &rep, nonce, p.base.Hostname(), p.now())
	if err != nil {
		var nerr *nearai.Error
		if errors.As(err, &nerr) && nerr.Retryable {
			return nil, core.Wrap(noCaller, core.CodeVerifierUnavailable, err, "TDX collateral unavailable")
		}
		return nil, core.Wrap(noCaller, core.CodeAttestationFailed, err, "verify attestation report")
	}
	// The report itself must have arrived over an attested TLS key. Without
	// one, which the verifier allows only with E2EE, the attested E2EE key
	// binds the channel instead.
	if len(id.TLSPins) > 0 && !peerPinned(resp.TLS, id.TLSPins) {
		return nil, core.Errorf(core.CodeTLSPinMismatch, ErrTLSPinMismatch, "attestation was served over a TLS key the keyset does not list")
	}
	return p.store(id)
}

// store records a verified identity as current, reusing the pinned transport
// of an earlier session for the same keyset, and drops expired keysets.
func (p *Provider) store(id *Identity) (*session, error) {
	now := p.now()
	expires := now.Add(identityMaxAge)
	if id.NotAfter.Before(expires) {
		expires = id.NotAfter
	}
	s := &session{id: id, expires: expires}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, p.errClosed()
	}
	if prev := p.known[id.KeysetDigest]; prev != nil {
		s.transport, s.client, s.streamClient = prev.transport, prev.client, prev.streamClient
	} else {
		if len(id.TLSPins) > 0 {
			s.transport = pinnedTransport(p.transport, id.TLSPins)
		} else {
			s.transport = p.transport.Clone()
		}
		s.client = newClient(s.transport, p.timeout)
		s.streamClient = newClient(s.transport, 0)
	}
	p.known[id.KeysetDigest] = s
	p.current = s
	for d, k := range p.known {
		if !now.Before(k.id.NotAfter) {
			delete(p.known, d)
			k.transport.CloseIdleConnections()
		}
	}
	return s, nil
}

// readLimited reads a whole body, failing rather than truncating when it
// exceeds maxBodyBytes: a truncated body could never match its receipt hash.
func readLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBodyBytes {
		return nil, fmt.Errorf("body exceeds %d bytes", maxBodyBytes)
	}
	return b, nil
}
